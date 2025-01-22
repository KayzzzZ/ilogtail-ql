// core/ebpf/driver/FilePluginStrategy.cpp
#include "FilePluginStrategy.h"
#include "CallName.h"

namespace logtail {
namespace ebpf {

FilePluginStrategy::FilePluginStrategy(
    const std::string& name,
    std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
    std::shared_ptr<FilterManager> filterManager) {
    mName = name;
    mWrapper = wrapper;
    mFilterManager = filterManager;
    mPerfManager = PerfBufferManager::Create(wrapper);
    
    // 初始化 mProgOps
    mProgOps.emplace_back("handle_open", true);
    mProgOps.emplace_back("handle_create", true);
}

void FilePluginStrategy::HandleEvent(void* ctx, int cpu, void* data, uint32_t size) {
    ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_DEBUG,
             "[FilePluginStrategy] Received event from CPU %d, size %u\n",
             cpu, size);
}

void FilePluginStrategy::HandleLostEvents(void* ctx, int cpu, __u64 lostCnt) {
    ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
             "[FilePluginStrategy] Lost %lu events on CPU %d\n",
             lostCnt, cpu);
}

int FilePluginStrategy::Start() {
    if (mIsRunning) {
        return 0;
    }

    // 1. 初始化 wrapper
    if (mWrapper->Init() != 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[FilePluginStrategy] Failed to init wrapper\n");
        return 1;
    }

    // 2. 创建 perf buffer
    mPerfManager->CreateBuffer(mName, 128, HandleEvent, HandleLostEvents);

    // 3. 设置 tail calls
    std::vector<std::string> functions = {"handle_open", "handle_create"};
    if (mWrapper->SetTailCall("prog_array", functions) != 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[FilePluginStrategy] Failed to set tail calls\n");
        return 1;
    }

    // 4. 设置 filter
    if (mFilterManager->CreateFilter(mWrapper, 
                                   FilterManager::FilterType::kFile, 
                                   "open", 
                                   mConfig) != 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[FilePluginStrategy] Failed to create filter\n");
        return 1;
    }

    // 5. attach programs
    if (mWrapper->DynamicAttachBPFObject(mProgOps) != 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[FilePluginStrategy] Failed to attach programs\n");
        return 1;
    }

    mIsRunning = true;
    return 0;
}

int FilePluginStrategy::Stop() {
    if (!mIsRunning) {
        return 0;
    }

    // 1. detach programs
    mWrapper->DynamicDetachBPFObject(mProgOps);

    // 2. 清理 filter
    mFilterManager->DeleteFilter(mWrapper, FilterManager::FilterType::kFile, "open");

    // 3. 删除 perf buffer
    mPerfManager->DeleteBuffer(mName);

    // 4. 销毁 wrapper
    mWrapper->Destroy();

    mIsRunning = false;
    return 0;
}

int FilePluginStrategy::Suspend() {
    if (!mIsRunning) {
        return 0;
    }
    return mWrapper->DynamicDetachBPFObject(mProgOps);
}

int FilePluginStrategy::Resume() {
    if (!mIsRunning) {
        return 1;
    }
    return mWrapper->DynamicAttachBPFObject(mProgOps);
}

int FilePluginStrategy::Update(
    const std::variant<std::monostate, SecurityFileFilter, SecurityNetworkFilter>& config) {
    if (!mIsRunning) {
        return 1;
    }

    if (auto fileFilter = std::get_if<SecurityFileFilter>(&config)) {
        // 1. 清理旧的 filter
        mFilterManager->DeleteFilter(mWrapper, FilterManager::FilterType::kFile, "open");

        // 2. 设置新的 filter
        mConfig = *fileFilter;
        return mFilterManager->CreateFilter(mWrapper, 
                                         FilterManager::FilterType::kFile, 
                                         "open", 
                                         mConfig);
    }
    return 1;
}

int FilePluginStrategy::PollPerfBuffer() {
    if (!mIsRunning) {
        return -1;
    }
    return mPerfManager->PollBuffer(mName, 64, 100);
}

} // namespace ebpf
} // namespace logtail