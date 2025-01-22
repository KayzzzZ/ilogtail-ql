// core/ebpf/driver/eBPFDriver.h
#pragma once

#include <memory>
#include <string>
#include <variant>
#include "BPFMapTraits.h"
#include "eBPFWrapper.h"
#include "ebpf/include/export.h"
#include "PluginStrategy.h"
#include "FilePluginStrategy.h"
#include "NetworkPluginStrategy.h"

namespace logtail {
namespace ebpf {

class eBPFDriver {
public:
    static eBPFDriver* GetInstance() { return sInstance; }
    static void Initialize();
    static void Cleanup();

    // 插件管理接口
    int StartPlugin(PluginConfig* config);
    int StopPlugin(PluginType type);
    int SuspendPlugin(PluginType type);
    int ResumePlugin(PluginType type);
    int UpdatePlugin(PluginConfig* config);
    int PollPluginPerfBuffers(PluginType type, int32_t maxEvents, int32_t* flag, int timeoutMs);

    // BPF Map 操作接口
    bool UpdateBPFMapElem(PluginType type, const std::string& mapName, void* key, void* value, uint64_t flag);
    bool LookupBPFMapElem(PluginType type, const std::string& mapName, void* key, void* value);
    bool DeleteBPFMapElem(PluginType type, const std::string& mapName, void* key);

    // 设置日志处理器
    void SetLogger(eBPFLogHandler fn);

private:
    eBPFDriver() = default;
    ~eBPFDriver() = default;

    std::shared_ptr<PluginStrategy> CreateStrategy(PluginType type);
    std::shared_ptr<PluginStrategy> GetStrategy(PluginType type);
    void CheckAndInitialize();

private:
    static eBPFDriver* sInstance;
    bool mInited = false;
    eBPFLogHandler mLogHandler = nullptr;
    std::shared_ptr<FilterManager> mFilterManager;
    std::unordered_map<PluginType, std::shared_ptr<PluginStrategy>> mStrategies;
    std::mutex mMutex;
};

} // namespace ebpf
} // namespace logtail
