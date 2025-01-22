// core/ebpf/driver/PerfBufferManager.cpp
#include "PerfBufferManager.h"

namespace logtail {
namespace ebpf {

void PerfBufferManager::CreateBuffer(const std::string& name, 
                                   int pageCnt,
                                   perf_buffer_sample_fn dataCb,
                                   perf_buffer_lost_fn lossCb) {
    std::lock_guard<std::mutex> lock(mMutex);
    auto context = std::make_shared<PerfBufferContext>();
    context->isValid = true;
    
    context->buffer = mWrapper->CreatePerfBuffer(name, pageCnt, nullptr, dataCb, lossCb);
    if (!context->buffer) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                 "[PerfBufferManager] Failed to create perf buffer: %s\n",
                 name.c_str());
        return;
    }
    
    mBuffers[name] = context;
    ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_INFO,
             "[PerfBufferManager] Created perf buffer: %s\n",
             name.c_str());
}

void PerfBufferManager::DeleteBuffer(const std::string& name) {
    std::shared_ptr<PerfBufferContext> context;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto it = mBuffers.find(name);
        if (it == mBuffers.end()) {
            return;
        }
        context = it->second;
        mBuffers.erase(it);
    }

    {
        std::lock_guard<std::mutex> bufferLock(context->mutex);
        context->isValid = false;
        if (context->buffer) {
            mWrapper->DeletePerfBuffer(context->buffer);
            context->buffer = nullptr;
        }
    }
    
    ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_INFO,
             "[PerfBufferManager] Deleted perf buffer: %s\n",
             name.c_str());
}

void PerfBufferManager::DeleteAllBuffers() {
    std::lock_guard<std::mutex> lock(mMutex);
    for (auto& pair : mBuffers) {
        auto& context = pair.second;
        std::lock_guard<std::mutex> bufferLock(context->mutex);
        context->isValid = false;
        if (context->buffer) {
            mWrapper->DeletePerfBuffer(context->buffer);
            context->buffer = nullptr;
        }
    }
    mBuffers.clear();
}

int PerfBufferManager::PollBuffer(const std::string& name, int maxEvents, int timeoutMs) {
    std::shared_ptr<PerfBufferContext> context;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto it = mBuffers.find(name);
        if (it == mBuffers.end()) {
            return -1;
        }
        context = it->second;
    }

    std::lock_guard<std::mutex> bufferLock(context->mutex);
    if (!context->isValid || !context->buffer) {
        return -1;
    }
    return mWrapper->PollPerfBuffer(context->buffer, maxEvents, timeoutMs);
}

} // namespace ebpf
} // namespace logtail
