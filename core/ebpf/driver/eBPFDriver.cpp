// core/ebpf/driver/eBPFDriver.cpp
#include "eBPFDriver.h"
#include "Log.h"
#include "ebpf/include/export.h"

namespace logtail {
namespace ebpf {

eBPFDriver* eBPFDriver::sInstance = nullptr;

void eBPFDriver::Initialize() {
    if (!sInstance) {
        sInstance = new eBPFDriver();
        if (sInstance) {
            sInstance->mFilterManager = FilterManager::Create();
            sInstance->mInited = true;
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_INFO,
                     "[eBPFDriver] Successfully initialized\n");
        }
    }
}

void eBPFDriver::Cleanup() {
    if (sInstance) {
        std::lock_guard<std::mutex> lock(sInstance->mMutex);
        for (auto& pair : sInstance->mStrategies) {
            auto& strategy = pair.second;
            if (strategy && strategy->IsRunning()) {
                strategy->Stop();
            }
        }
        sInstance->mStrategies.clear();
        delete sInstance;
        sInstance = nullptr;
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_INFO,
                 "[eBPFDriver] Successfully cleaned up\n");
    }
}

void eBPFDriver::SetLogger(eBPFLogHandler fn) {
    std::lock_guard<std::mutex> lock(mMutex);
    mLogHandler = fn;
    if (mLogHandler) {
        set_log_handler(mLogHandler);
    }
}

void eBPFDriver::CheckAndInitialize() {
    if (!mInited) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (!mInited) {
            mFilterManager = FilterManager::Create();
            mInited = true;
        }
    }
}

std::shared_ptr<PluginStrategy> eBPFDriver::CreateStrategy(PluginType type) {
    auto wrapper = std::make_shared<BPFWrapper<security_bpf>>();
    
    switch (type) {
        case PluginType::FILE_SECURITY:
            return FilePluginStrategy::Create("file_security", wrapper, mFilterManager);
        case PluginType::NETWORK_SECURITY:
            return NetworkPluginStrategy::Create("network_security", wrapper, mFilterManager);
        default:
            ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                     "[eBPFDriver] Unsupported plugin type: %d\n",
                     static_cast<int>(type));
            return nullptr;
    }
}

std::shared_ptr<PluginStrategy> eBPFDriver::GetStrategy(PluginType type) {
    std::lock_guard<std::mutex> lock(mMutex);
    auto it = mStrategies.find(type);
    if (it != mStrategies.end()) {
        return it->second;
    }
    return nullptr;
}

int eBPFDriver::StartPlugin(PluginConfig* config) {
    if (!config) {
        ebpf_log(logtail::ebpf::eBPFLogType::NAMI_LOG_TYPE_WARN,
                 "[eBPFDriver] Invalid config pointer\n");
        return 1;
    }

    CheckAndInitialize();

    auto type = config->mPluginType;
    auto strategy = GetStrategy(type);
    if (!strategy) {
        strategy = CreateStrategy(type);
        if (!strategy) {
            return 1;
        }
        std::lock_guard<std::mutex> lock(mMutex);
        mStrategies[type] = strategy;
    }

    return strategy->Start();
}

int eBPFDriver::StopPlugin(PluginType type) {
    auto strategy = GetStrategy(type);
    if (!strategy) {
        return 0;
    }

    int ret = strategy->Stop();
    if (ret == 0) {
        std::lock_guard<std::mutex> lock(mMutex);
        mStrategies.erase(type);
    }
    return ret;
}

int eBPFDriver::SuspendPlugin(PluginType type) {
    auto strategy = GetStrategy(type);
    if (!strategy) {
        return 0;
    }
    return strategy->Suspend();
}

int eBPFDriver::ResumePlugin(PluginType type) {
    auto strategy = GetStrategy(type);
    if (!strategy) {
        return 1;
    }
    return strategy->Resume();
}

int eBPFDriver::UpdatePlugin(PluginConfig* config) {
    if (!config) {
        return 1;
    }

    auto type = config->mPluginType;
    auto strategy = GetStrategy(type);
    if (!strategy) {
        return 1;
    }

    // return strategy->Update(config->mConfig);
    // TODO @qianlu.kk
    return 0;
}

int eBPFDriver::PollPluginPerfBuffers(PluginType type, int32_t maxEvents, int32_t* flag, int timeoutMs) {
    auto strategy = GetStrategy(type);
    if (!strategy) {
        return -1;
    }
    return strategy->PollPerfBuffer();
}

bool eBPFDriver::UpdateBPFMapElem(PluginType type, const std::string& mapName, void* key, void* value, uint64_t flag) {
    auto strategy = GetStrategy(type);
    if (!strategy || !strategy->IsRunning()) {
        return false;
    }
    // 通过 strategy 获取 wrapper 并更新 map
    // TODO: 实现具体逻辑
    return true;
}

bool eBPFDriver::LookupBPFMapElem(PluginType type, const std::string& mapName, void* key, void* value) {
    auto strategy = GetStrategy(type);
    if (!strategy || !strategy->IsRunning()) {
        return false;
    }
    // TODO: 实现具体逻辑
    return true;
}

bool eBPFDriver::DeleteBPFMapElem(PluginType type, const std::string& mapName, void* key) {
    auto strategy = GetStrategy(type);
    if (!strategy || !strategy->IsRunning()) {
        return false;
    }
    // TODO: 实现具体逻辑
    return true;
}

// C 接口实现
extern "C" {

// void initialize_ebpf_driver() {
//     eBPFDriver::Initialize();
// }

// void cleanup_ebpf_driver() {
//     eBPFDriver::Cleanup();
// }

// void set_logger(eBPFLogHandler fn) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         driver->SetLogger(fn);
//     }
// }

// int start_plugin(PluginConfig* config) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->StartPlugin(config);
//     }
//     return 1;
// }

// int stop_plugin(PluginType type) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->StopPlugin(type);
//     }
//     return 1;
// }

// int suspend_plugin(PluginType type) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->SuspendPlugin(type);
//     }
//     return 1;
// }

// int resume_plugin(PluginType type) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->ResumePlugin(type);
//     }
//     return 1;
// }

// int update_plugin(PluginConfig* config) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->UpdatePlugin(config);
//     }
//     return 1;
// }

// int poll_plugin_pbs(PluginType type, int32_t maxEvents, int32_t* flag, int timeoutMs) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->PollPluginPerfBuffers(type, maxEvents, flag, timeoutMs);
//     }
//     return -1;
// }

// bool update_bpf_map_elem(PluginType type, const char* mapName, void* key, void* value, uint64_t flag) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->UpdateBPFMapElem(type, mapName, key, value, flag);
//     }
//     return false;
// }

// bool lookup_bpf_map_elem(PluginType type, const char* mapName, void* key, void* value) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->LookupBPFMapElem(type, mapName, key, value);
//     }
//     return false;
// }

// bool delete_bpf_map_elem(PluginType type, const char* mapName, void* key) {
//     if (auto driver = eBPFDriver::GetInstance()) {
//         return driver->DeleteBPFMapElem(type, mapName, key);
//     }
//     return false;
// }

} // extern "C"

} // namespace ebpf
} // namespace logtail
