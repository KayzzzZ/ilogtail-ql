// core/ebpf/driver/FilterManager.cpp
#include "FilterManager.h"
#include "Log.h"
#include "CallName.h"
#include "IdAllocator.h"

namespace logtail {
namespace ebpf {

int FilterManager::CreateFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                              FilterType type,
                              const std::string& callName,
                              const std::variant<std::monostate, SecurityFileFilter, SecurityNetworkFilter>& config) {
    if (type == FilterType::kFile) {
        if (auto fileFilter = std::get_if<SecurityFileFilter>(&config)) {
            return CreateFileFilter(wrapper, callName, *fileFilter);
        }
    } else if (type == FilterType::kNetwork) {
        if (auto networkFilter = std::get_if<SecurityNetworkFilter>(&config)) {
            return CreateNetworkFilter(wrapper, callName, *networkFilter);
        }
    }
    return 1;
}

int FilterManager::DeleteFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                              FilterType type,
                              const std::string& callName) {
    if (type == FilterType::kFile) {
        return DeleteFileFilter(wrapper, callName);
    } else if (type == FilterType::kNetwork) {
        return DeleteNetworkFilter(wrapper, callName);
    }
    return 1;
}

int FilterManager::CreateFileFilter(std::shared_ptr<BPFWrapper<security_bpf>> wrapper,
                                  const std::string& callName,
                                  const SecurityFileFilter& config) {
    int call_name_idx = GetCallNameIdx(callName);
    if (call_name_idx < 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN, 
                 "[CreateFileFilter] Invalid call name: %s\n", 
                 callName.c_str());
        return 1;
    }

    selector_filters kernel_filters;
    ::memset(&kernel_filters, 0, sizeof(kernel_filters));

    int idx = IdAllocator::GetInstance()->GetNextId<StringPrefixMap>();
    if (idx < 0) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                 "[CreateFileFilter] Failed to get next id\n");
        return 1;
    }

    selector_filter k_filter;
    ::memset(&k_filter, 0, sizeof(k_filter));
    k_filter.filter_type = FILTER_TYPE_FILE_PREFIX;
    k_filter.map_idx[0] = idx;
    kernel_filters.filter_count = 1;
    kernel_filters.filters[0] = k_filter;

    for (const auto& path : config.mFilePathList) {
        string_prefix_lpm_trie prefix_trie;
        ::memset(&prefix_trie, 0, sizeof(prefix_trie));
        ::memcpy(prefix_trie.data, path.data(), path.length());
        prefix_trie.prefixlen = path.length() * 8;
        uint8_t val = 1;

        int ret = wrapper->UpdateInnerMapElem<StringPrefixMap>(
            "string_prefix_maps", &idx, &prefix_trie, &val, 0);
        if (ret) {
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                     "[CreateFileFilter] Failed to update inner map for path: %s\n",
                     path.c_str());
            continue;
        }
    }

    return wrapper->UpdateBPFHashMap("filter_map", &call_name_idx, &kernel_filters, 0);
}

// 其他方法实现类似...

} // namespace ebpf
} // namespace logtail
