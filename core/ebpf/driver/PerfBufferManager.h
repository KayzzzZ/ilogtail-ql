// core/ebpf/driver/PerfBufferManager.h
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <atomic>
#include "BPFMapTraits.h"
#include "eBPFWrapper.h"
#include "Log.h"
#include "coolbpf/src/security/security.skel.h"

namespace logtail {
namespace ebpf {

class PerfBufferManager {
public:
    struct PerfBufferContext {
        void* buffer;
        std::atomic<bool> isValid;
        std::mutex mutex;
    };

    static std::shared_ptr<PerfBufferManager> Create(std::shared_ptr<BPFWrapper<security_bpf>> wrapper) {
        return std::make_shared<PerfBufferManager>(wrapper);
    }

    explicit PerfBufferManager(std::shared_ptr<BPFWrapper<security_bpf>> wrapper) 
        : mWrapper(wrapper) {}

    ~PerfBufferManager() {
        DeleteAllBuffers();
    }

    void CreateBuffer(const std::string& name, 
                     int pageCnt,
                     perf_buffer_sample_fn dataCb,
                     perf_buffer_lost_fn lossCb);

    void DeleteBuffer(const std::string& name);

    void DeleteAllBuffers();

    int PollBuffer(const std::string& name, int maxEvents, int timeoutMs);

private:
    std::shared_ptr<BPFWrapper<security_bpf>> mWrapper;
    std::mutex mMutex;
    std::unordered_map<std::string, std::shared_ptr<PerfBufferContext>> mBuffers;
};

} // namespace ebpf
} // namespace logtail
