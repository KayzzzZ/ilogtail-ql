// core/ebpf/driver/FilePluginStrategy.h
#pragma once

#include "PluginStrategy.h"

namespace logtail {
namespace ebpf {


class FilePluginStrategy : public PluginStrategy {
public:
    static std::shared_ptr<FilePluginStrategy> Create(
        const std::string& name,
        std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
        std::shared_ptr<FilterManager> filterManager) {
        return std::make_shared<FilePluginStrategy>(name, wrapper, filterManager);
    }

    FilePluginStrategy(const std::string& name,
                      std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                      std::shared_ptr<FilterManager> filterManager);
                      
    int Start() override;
    int Stop() override;
    int Suspend() override;
    int Resume() override;
    int Update(const std::variant<std::monostate, SecurityFileFilter, SecurityNetworkFilter>& config) override;
    int PollPerfBuffer() override;

private:
    SecurityFileFilter mConfig;
    std::vector<AttachProgOps> mProgOps;
    static void HandleEvent(void* ctx, int cpu, void* data, uint32_t size);
    static void HandleLostEvents(void* ctx, int cpu, __u64 lostCnt);
};

} // namespace ebpf
} // namespace logtail
