// core/ebpf/driver/FilterManager.h
#pragma once

#include <memory>
#include <string>
#include <variant>
#include "BPFMapTraits.h"
#include "eBPFWrapper.h"
#include "ebpf/include/export.h"
#include "coolbpf/src/security/security.skel.h"

namespace logtail {
namespace ebpf {

class FilterManager {
public:
    enum class FilterType {
        kFile,
        kNetwork
    };

    static std::shared_ptr<FilterManager> Create() {
        return std::make_shared<FilterManager>();
    }

    int CreateFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                    FilterType type,
                    const std::string& callName,
                    const std::variant<std::monostate, SecurityFileFilter, SecurityNetworkFilter>& config);
                    
    int DeleteFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                    FilterType type,
                    const std::string& callName);

private:
    int CreateFileFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                        const std::string& callName,
                        const SecurityFileFilter& config);
                        
    int CreateNetworkFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                           const std::string& callName,
                           const SecurityNetworkFilter& config);
                           
    int DeleteFileFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                        const std::string& callName);
                        
    int DeleteNetworkFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                           const std::string& callName);
};

} // namespace ebpf
} // namespace logtail