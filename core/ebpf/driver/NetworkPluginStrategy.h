// core/ebpf/driver/NetworkPluginStrategy.h
#pragma once

#include "PluginStrategy.h"
#include "coolbpf/src/security/security.skel.h"

namespace logtail {
namespace ebpf {

class NetworkPluginStrategy : public PluginStrategy {
public:
    static std::shared_ptr<NetworkPluginStrategy> Create(
        const std::string& name,
        std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
        std::shared_ptr<FilterManager> filterManager) {
        return std::make_shared<NetworkPluginStrategy>(name, wrapper, filterManager);
    }

    NetworkPluginStrategy(const std::string& name,
                         std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                         std::shared_ptr<FilterManager> filterManager);
                      
    int Start() override;
    int Stop() override;
    int Suspend() override;
    int Resume() override;
    int Update(const std::variant<std::monostate, SecurityFileFilter, SecurityNetworkFilter>& config) override;
    int PollPerfBuffer() override;

private:
    SecurityNetworkFilter mConfig;
    std::vector<AttachProgOps> mProgOps;
    static void HandleEvent(void* ctx, int cpu, void* data, uint32_t size);
    static void HandleLostEvents(void* ctx, int cpu, __u64 lostCnt);

    static constexpr const char* PERF_BUFFER = "network_events";
};

} // namespace ebpf
} // namespace logtail