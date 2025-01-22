// core/ebpf/driver/PluginStrategy.h
#pragma once

#include <memory>
#include <string>
#include <variant>
#include "BPFMapTraits.h"
#include "eBPFWrapper.h"
#include "ebpf/include/export.h"
#include "coolbpf/src/security/security.skel.h"
#include "FilterManager.h"
#include "PerfBufferManager.h"

namespace logtail {
namespace ebpf {

class PluginStrategy {
public:
    virtual ~PluginStrategy() = default;
    
    virtual int Start() = 0;
    virtual int Stop() = 0;
    virtual int Suspend() = 0;
    virtual int Resume() = 0;
    virtual int Update(const std::variant<std::monostate, SecurityFileFilter, SecurityNetworkFilter>& config) = 0;
    virtual int PollPerfBuffer() = 0;
    
    bool IsRunning() const { return mIsRunning; }

protected:
    std::shared_ptr<BPFWrapper<security_bpf>> mWrapper;
    std::shared_ptr<FilterManager> mFilterManager;
    std::shared_ptr<PerfBufferManager> mPerfManager;
    std::string mName;
    bool mIsRunning = false;
};

} // namespace ebpf
} // namespace logtail