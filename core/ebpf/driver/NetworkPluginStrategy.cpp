// core/ebpf/driver/NetworkPluginStrategy.cpp
#include "NetworkPluginStrategy.h"
#include "CallName.h"

namespace logtail {
namespace ebpf {

NetworkPluginStrategy::NetworkPluginStrategy(
    const std::string& name,
    std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
    std::shared_ptr<FilterManager> filterManager) {
    mName = name;
    mWrapper = wrapper;
    mFilterManager = filterManager;
    mPerfManager = PerfBufferManager::Create(wrapper);
    
    // 初始化 mProgOps，对应 security.bpf.c 中的程序
    mProgOps.emplace_back("security_connect", true);
    mProgOps.emplace_back("security_connect_v6", true);
    mProgOps.emplace_back("security_bind", true);
    mProgOps.emplace_back("security_bind_v6", true);
}

void NetworkPluginStrategy::HandleEvent(void* ctx, int cpu, void* data, uint32_t size) {
    ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
             "[NetworkPluginStrategy] Received event from CPU %d, size %u\n",
             cpu, size);
}

void NetworkPluginStrategy::HandleLostEvents(void* ctx, int cpu, __u64 lostCnt) {
    ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
             "[NetworkPluginStrategy] Lost %lu events on CPU %d\n",
             lostCnt, cpu);
}

int NetworkPluginStrategy::Start() {
    if (mIsRunning) {
        return 0;
    }

    // 1. 初始化 wrapper
    if (mWrapper->Init() != 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[NetworkPluginStrategy] Failed to init wrapper\n");
        return 1;
    }

    // 2. 创建 perf buffer
    mPerfManager->CreateBuffer(PERF_BUFFER, 128, HandleEvent, HandleLostEvents);

    // 3. 设置 tail calls
    std::vector<std::string> functions = {
        "security_connect", "security_connect_v6",
        "security_bind", "security_bind_v6"
    };
    if (mWrapper->SetTailCall("security_progs", functions) != 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[NetworkPluginStrategy] Failed to set tail calls\n");
        return 1;
    }

    // 4. 设置 filter
    if (mFilterManager->CreateFilter(mWrapper, 
                                   FilterManager::FilterType::kNetwork, 
                                   "connect", 
                                   mConfig) != 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[NetworkPluginStrategy] Failed to create filter\n");
        return 1;
    }

    // 5. attach programs
    if (mWrapper->DynamicAttachBPFObject(mProgOps) != 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[NetworkPluginStrategy] Failed to attach programs\n");
        return 1;
    }

    mIsRunning = true;
    return 0;
}

int NetworkPluginStrategy::Stop() {
    if (!mIsRunning) {
        return 0;
    }

    // 1. detach programs
    mWrapper->DynamicDetachBPFObject(mProgOps);

    // 2. 清理 filter
    mFilterManager->DeleteFilter(mWrapper, FilterManager::FilterType::kNetwork, "connect");

    // 3. 删除 perf buffer
    mPerfManager->DeleteBuffer(PERF_BUFFER);

    // 4. 销毁 wrapper
    mWrapper->Destroy();

    mIsRunning = false;
    return 0;
}

int NetworkPluginStrategy::Suspend() {
    if (!mIsRunning) {
        return 0;
    }
    return mWrapper->DynamicDetachBPFObject(mProgOps);
}

int NetworkPluginStrategy::Resume() {
    if (!mIsRunning) {
        return 1;
    }
    return mWrapper->DynamicAttachBPFObject(mProgOps);
}

int NetworkPluginStrategy::Update(
    const std::variant<std::monostate, SecurityFileFilter, SecurityNetworkFilter>& config) {
    if (!mIsRunning) {
        return 1;
    }

    if (auto networkFilter = std::get_if<SecurityNetworkFilter>(&config)) {
        // 1. 清理旧的 filter
        mFilterManager->DeleteFilter(mWrapper, FilterManager::FilterType::kNetwork, "connect");

        // 2. 设置新的 filter
        mConfig = *networkFilter;
        return mFilterManager->CreateFilter(mWrapper, 
                                         FilterManager::FilterType::kNetwork, 
                                         "connect", 
                                         mConfig);
    }
    return 1;
}

int NetworkPluginStrategy::PollPerfBuffer() {
    if (!mIsRunning) {
        return -1;
    }
    return mPerfManager->PollBuffer(PERF_BUFFER, 64, 100);
}

} // namespace ebpf
} // namespace logtail
