// Copyright 2023 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <gflags/gflags.h>

#include "app_config/AppConfig.h"
#include "ebpf/config.h"
#include "ebpf/eBPFServer.h"
#include "logger/Logger.h"
#include "ebpf/include/export.h"
#include "common/LogtailCommonFlags.h"
#include "common/MachineInfoUtil.h"
#include "pipeline/queue/ProcessQueueItem.h"
#include "pipeline/queue/ProcessQueueManager.h"


DEFINE_FLAG_INT64(kernel_min_version_for_ebpf,
                  "the minimum kernel version that supported eBPF normal running, 4.19.0.0 -> 4019000000",
                  4019000000);

namespace logtail {
namespace ebpf {

static const uint16_t KERNEL_VERSION_310 = 3010; // for centos7
static const std::string KERNEL_NAME_CENTOS = "CentOS";
static const uint16_t KERNEL_CENTOS_MIN_VERSION = 7006;

bool EnvManager::IsSupportedEnv(nami::PluginType type) {
    if (!mInited) {
        LOG_ERROR(sLogger, ("env manager not inited ...", ""));
        return false;
    }
    bool status = false;
    switch (type)
    {
    case nami::PluginType::NETWORK_OBSERVE:
        status = mArchSupport && (mBTFSupport || m310Support);
        break;
    case nami::PluginType::FILE_SECURITY:
    case nami::PluginType::NETWORK_SECURITY:
    case nami::PluginType::PROCESS_SECURITY: {
        status = mArchSupport && mBTFSupport;
        break;
    }
    default:
        status = false;
    }
    if (!status) {
        LOG_WARNING(sLogger, ("runtime env not supported, plugin type: ", int(type)) 
            ("arch support is ", mArchSupport) ("btf support is ", mBTFSupport) ("310 support is ", m310Support));
    }
    return status;
}

bool EnvManager::AbleToLoadDyLib() {
    return mArchSupport;
}

void EnvManager::InitEnvInfo() {
    if (mInited) return;
    mInited = true;

#ifdef _MSC_VER
    LOG_WARNING(sLogger, ("MS", "not supported"));
    mArchSupport = false;
    return;
#elif defined(__aarch64__)
    LOG_WARNING(sLogger, ("aarch64", "not supported"));
    mArchSupport = false;
    return;
#elif defined(__arm__)
    LOG_WARNING(sLogger, ("arm", "not supported"));
    mArchSupport = false;
    return;
#elif defined(__i386__)
    LOG_WARNING(sLogger, ("i386", "not supported"));
    mArchSupport = false;
    return;
#endif
    mArchSupport = true;
    std::string release;
    int64_t version;
    GetKernelInfo(release, version);
    LOG_INFO(sLogger, ("ebpf kernel release", release) ("kernel version", version));
    if (release.empty()) {
        LOG_WARNING(sLogger, ("cannot find kernel release", ""));
        mBTFSupport = false;
        return;
    }
    if (version >= INT64_FLAG(kernel_min_version_for_ebpf)) {
        mBTFSupport = true;
        return;
    }
    if (version / 1000000 != KERNEL_VERSION_310) {
        LOG_WARNING(sLogger, 
            ("unsupported kernel version, will not start eBPF plugin ... version", version));
        m310Support = false;
        return;
    }

    std::string os;
    int64_t osVersion;
    if (GetRedHatReleaseInfo(os, osVersion, STRING_FLAG(default_container_host_path))
        || GetRedHatReleaseInfo(os, osVersion)) {
        if(os == KERNEL_NAME_CENTOS && osVersion >= KERNEL_CENTOS_MIN_VERSION) {
            m310Support = true;
            return;
        } else {
            LOG_WARNING(sLogger, 
                ("unsupported os for 310 kernel, will not start eBPF plugin ...", "") 
                ("os", os)("version", osVersion));
            m310Support = false;
            return;
        }
    }
    LOG_WARNING(sLogger, 
        ("not redhat release, will not start eBPF plugin ...", ""));
    m310Support = false;
    return;
}

bool eBPFServer::IsSupportedEnv(nami::PluginType type) {
    return mEnvMgr.IsSupportedEnv(type);
}

void eBPFServer::Init() {
    if (mInited) {
        return;
    }
    mEnvMgr.InitEnvInfo();
    if (!mEnvMgr.AbleToLoadDyLib()) {
        return;
    }
    mInited = true;
    mSourceManager = std::make_unique<SourceManager>();
    mSourceManager->Init();
    // ebpf config
    auto configJson = AppConfig::GetInstance()->GetConfig();
    mAdminConfig.LoadEbpfConfig(configJson);
    mEventCB = std::make_unique<EventHandler>(nullptr, -1, 0);
#ifdef __ENTERPRISE__
    mMeterCB = std::make_unique<ArmsMeterHandler>(nullptr, -1, 0);
    mSpanCB = std::make_unique<ArmsSpanHandler>(nullptr, -1, 0);
#else
    mMeterCB = std::make_unique<OtelMeterHandler>(nullptr, -1, 0);
    mSpanCB = std::make_unique<OtelSpanHandler>(nullptr, -1, 0);
#endif

    mNetworkSecureCB = std::make_unique<SecurityHandler>(nullptr, -1, 0);
    mProcessSecureCB = std::make_unique<SecurityHandler>(nullptr, -1, 0);
    mFileSecureCB = std::make_unique<SecurityHandler>(nullptr, -1, 0);
}

void eBPFServer::Stop() {
    if (!mInited) return;
    mInited = false;
    LOG_INFO(sLogger, ("begin to stop all plugins", ""));
    mSourceManager->StopAll();
    // destroy source manager 
    mSourceManager.reset();
    for (std::size_t i = 0; i < mLoadedPipeline.size(); i ++) {
        UpdatePipelineName(static_cast<nami::PluginType>(i), "");
    }
    
    // UpdateContext must after than StopPlugin
    if (mEventCB) mEventCB->UpdateContext(nullptr, -1, -1);
    if (mMeterCB) mMeterCB->UpdateContext(nullptr, -1, -1);
    if (mSpanCB) mSpanCB->UpdateContext(nullptr,-1, -1);
    if (mNetworkSecureCB) mNetworkSecureCB->UpdateContext(nullptr,-1, -1);
    if (mProcessSecureCB) mProcessSecureCB->UpdateContext(nullptr,-1, -1);
    if (mFileSecureCB) mFileSecureCB->UpdateContext(nullptr, -1, -1);
}

void eBPFServer::GenerateMetric(logtail::QueueKey key, uint32_t idx) {
    LOG_INFO(sLogger, ("[ObserverServer] enter metric generator", ""));
    const std::vector<std::string> app_metric_names = {
                            "arms_rpc_requests_count", 
                            "arms_rpc_requests_slow_count", 
                            "arms_rpc_requests_error_count",
                            "arms_rpc_requests_seconds",
                            "arms_rpc_requests_by_status_count",
                        };
    const std::vector<std::string> tcp_metrics_names = {
                            "arms_npm_tcp_rtt_avg", 
                            "arms_npm_tcp_count_by_state", 
                            "arms_npm_tcp_conn_stats_count",
                            "arms_npm_tcp_drop_count",
                            "arms_npm_tcp_retrans_total",
                            "arms_npm_recv_packets_total",
                            "arms_npm_sent_packets_total",
                            "arms_npm_recv_bytes_total",
                            "arms_npm_sent_bytes_total",
    };
    // generate metrics
    while (mGenerateFlag) {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        std::vector<std::unique_ptr<ProcessQueueItem>> items;
        // construct vector<PipelineEventGroup>
        // 1000 timeseries for app
        std::vector<std::string> app_ids = {
            "eeeb8df999f59f569da84d27fa408a94", 
            "deddf8ef215107d8fd37540ac4e3291b", 
            "52abe1564d8ee3fea66e9302fc21d80d", 
            "87f79be5ab74d72b4a10b62c02dc7f34", 
            "1796627f8e0b7fbba042c145820311f9"
        };
        for (size_t i = 0; i < app_ids.size(); i ++) {
            std::shared_ptr<SourceBuffer> mSourceBuffer = std::make_shared<SourceBuffer>();;
            PipelineEventGroup mTestEventGroup(mSourceBuffer);
            mTestEventGroup.SetTag(std::string("pid"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("appId"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("source_ip"), "10.54.0.55");
            mTestEventGroup.SetTag(std::string("source"), std::string("ebpf"));
            mTestEventGroup.SetTag(std::string("appType"), std::string("EBPF"));
            for (size_t j = 0 ; j < app_metric_names.size(); j ++) {
                for (size_t z = 0; z < 10; z ++ ) {
                    auto metricsEvent = mTestEventGroup.AddMetricEvent();
                    metricsEvent->SetTag(std::string("workloadName"), std::string("arms-oneagent-test-ql"));
                    metricsEvent->SetTag(std::string("workloadKind"), std::string("faceless"));
                    metricsEvent->SetTag(std::string("source_ip"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("host"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("rpc"), std::string("/oneagent/qianlu/local" + std::to_string(z)));
                    metricsEvent->SetTag(std::string("rpcType"), std::string("0"));
                    metricsEvent->SetTag(std::string("callType"), std::string("http"));
                    metricsEvent->SetTag(std::string("statusCode"), std::string("200"));
                    metricsEvent->SetTag(std::string("version"), std::string("HTTP1.1"));
                    metricsEvent->SetName(app_metric_names[j]);
                    metricsEvent->SetValue(UntypedSingleValue{10.0});
                    metricsEvent->SetTimestamp(seconds);
                }
            }
            std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(mTestEventGroup), idx);
            items.emplace_back(std::move(item));
        }
        // tcp_metrics
        for (size_t i = 0; i < app_ids.size(); i ++)  {
            std::shared_ptr<SourceBuffer> mSourceBuffer = std::make_shared<SourceBuffer>();;
            PipelineEventGroup mTestEventGroup(mSourceBuffer);
            mTestEventGroup.SetTag(std::string("pid"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("appId"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("source_ip"), "10.54.0.44");
            mTestEventGroup.SetTag(std::string("source"), std::string("ebpf"));
            mTestEventGroup.SetTag(std::string("appType"), std::string("EBPF"));
            for (size_t j = 0 ; j < tcp_metrics_names.size(); j ++) {
                for (size_t z = 0; z < 20; z ++ ) {
                    auto metricsEvent = mTestEventGroup.AddMetricEvent();
                    metricsEvent->SetName(tcp_metrics_names[j]);
                    metricsEvent->SetTag(std::string("workloadName"), std::string("arms-oneagent-test-ql"));
                    metricsEvent->SetTag(std::string("workloadKind"), std::string("qianlu"));
                    metricsEvent->SetTag(std::string("source_ip"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("host"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("dest_ip"), std::string("10.54.0." + std::to_string(z)));
                    metricsEvent->SetTag(std::string("callType"), std::string("conn_stats"));
                    metricsEvent->SetValue(UntypedSingleValue{20.0});
                    metricsEvent->SetTimestamp(seconds);
                }
            }
            std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(mTestEventGroup), idx);
            items.emplace_back(std::move(item));
        }
        // push vector<PipelineEventGroup>
        for (size_t i = 0; i < items.size(); i ++) {
            auto status =ProcessQueueManager::GetInstance()->PushQueue(key, std::move(items[i]));
            if (status) {
                LOG_WARNING(sLogger, ("[Metrics] push queue failed! status", status));
            } else {
                LOG_INFO(sLogger, ("[Metrics] push queue success!", ""));
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
    LOG_INFO(sLogger, ("[Observer] exit metrics generator", ""));
}

void eBPFServer::GenerateSpan(logtail::QueueKey key, uint32_t idx) {

}

void eBPFServer::GenerateAgentInfo(logtail::QueueKey key, uint32_t idx) {
    LOG_INFO(sLogger, ("[ObserverServer] enter agentinfo generator", ""));
    while(mGenerateFlag) {
        std::shared_ptr<SourceBuffer> sourceBuffer = std::make_shared<SourceBuffer>();
        PipelineEventGroup eventGroup(sourceBuffer);
        const std::string key0 = "key0";
        const std::string key1 = "key1";
        const std::string key2 = "key2";
        const std::string key3 = "key3";

        const std::string val0 = "val0";
        const std::string val1 = "val1";
        const std::string val2 = "val2";
        const std::string val3 = "val3";
        const std::string app_id_key = "appId";
        const std::string app_prefix = "app-";
        for (int i = 0; i < 50; i ++) {
            std::string app = app_prefix + std::to_string(i);
            auto logEvent = eventGroup.AddLogEvent();
            logEvent->SetContent(app_id_key, app);
            logEvent->SetContent(key0, val0);
            logEvent->SetContent(key1, val1);
            logEvent->SetContent(key2, val2);
            logEvent->SetContent(key3, val3);
            auto now = std::chrono::steady_clock::now();
            logEvent->SetTimestamp(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        }
        std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(eventGroup), idx);
        auto res = ProcessQueueManager::GetInstance()->PushQueue(key, std::move(item));
        if (res) {
            LOG_WARNING(sLogger, ("[AgentInfo] push queue failed! status", res));
        } else {
            LOG_INFO(sLogger, ("[AgentInfo] push queue success!", ""));
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
    LOG_INFO(sLogger, ("[Observer] exit agentinfo generator", ""));
}

bool eBPFServer::StartPluginInternal(const std::string& pipeline_name, uint32_t plugin_index,
                        nami::PluginType type, 
                        const logtail::PipelineContext* ctx, 
                        const std::variant<SecurityOptions*, nami::ObserverNetworkOption*> options) {

    std::string prev_pipeline_name = CheckLoadedPipelineName(type);
    if (prev_pipeline_name.size() && prev_pipeline_name != pipeline_name) {
        LOG_WARNING(sLogger, ("pipeline already loaded, plugin type", int(type))
            ("prev pipeline", prev_pipeline_name)("curr pipeline", pipeline_name));
        return false;
    }

    UpdatePipelineName(type, pipeline_name);

    // step1: convert options to export type
    std::variant<nami::NetworkObserveConfig, nami::ProcessConfig, nami::NetworkSecurityConfig, nami::FileSecurityConfig> config;
    bool ret = false;
    // call update function
    // step2: call init function
    switch(type) {
    case nami::PluginType::PROCESS_SECURITY: {
        nami::ProcessConfig pconfig;
        pconfig.process_security_cb_ = [this](auto events) { return mProcessSecureCB->handle(std::move(events)); };
        SecurityOptions* opts = std::get<SecurityOptions*>(options);
        pconfig.options_ = opts->mOptionList;
        config = std::move(pconfig);
        // UpdateContext must ahead of StartPlugin
        mProcessSecureCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
        ret = mSourceManager->StartPlugin(type, config);
        break;
    }

    case nami::PluginType::NETWORK_OBSERVE:{
        nami::NetworkObserveConfig nconfig;
        nami::ObserverNetworkOption* opts = std::get<nami::ObserverNetworkOption*>(options);
        mGenerateFlag = true;
        if (opts->mEnableMetric) {
            nconfig.enable_metric_ = true;
            nconfig.measure_cb_ = [this](auto events, auto ts) { return mMeterCB->handle(std::move(events), ts); };
            mMeterCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
            mLogMockThread = std::thread(&eBPFServer::GenerateAgentInfo, this, ctx->GetProcessQueueKey(), plugin_index);
            mMetricMockThread = std::thread(&eBPFServer::GenerateMetric, this, ctx->GetProcessQueueKey(), plugin_index);
        }
        if (opts->mEnableSpan) {
            nconfig.enable_span_ = true;
            nconfig.span_cb_ = [this](auto events) { return mSpanCB->handle(std::move(events)); };
            mSpanCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
            mTraceMockThread = std::thread(&eBPFServer::GenerateSpan, this, ctx->GetProcessQueueKey(), plugin_index);
        }
        if (opts->mEnableLog) {
            nconfig.enable_event_ = true;
            nconfig.event_cb_ = [this](auto events) { return mEventCB->handle(std::move(events)); };
            mEventCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
            mLogMockThread = std::thread(&eBPFServer::GenerateAgentInfo, this, ctx->GetProcessQueueKey(), plugin_index);
        }

        config = std::move(nconfig);
        ret = mSourceManager->StartPlugin(type, config);

        break;
    }

    case nami::PluginType::NETWORK_SECURITY:{
        nami::NetworkSecurityConfig nconfig;
        nconfig.network_security_cb_ = [this](auto events) { return mNetworkSecureCB->handle(std::move(events)); };
        SecurityOptions* opts = std::get<SecurityOptions*>(options);
        nconfig.options_ = opts->mOptionList;
        config = std::move(nconfig);
        // UpdateContext must ahead of StartPlugin
        mNetworkSecureCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
        ret = mSourceManager->StartPlugin(type, config);
        break;
    }

    case nami::PluginType::FILE_SECURITY:{
        nami::FileSecurityConfig fconfig;
        fconfig.file_security_cb_ = [this](auto events) { return mFileSecureCB->handle(std::move(events)); };
        SecurityOptions* opts = std::get<SecurityOptions*>(options);
        fconfig.options_ = opts->mOptionList;
        config = std::move(fconfig);
        // UpdateContext must ahead of StartPlugin
        mFileSecureCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
        ret = mSourceManager->StartPlugin(type, config);
        break;
    }
    default:
        LOG_ERROR(sLogger, ("unknown plugin type", int(type)));
        return false;
    }

    return ret;
}

bool eBPFServer::HasRegisteredPlugins() const {
    std::lock_guard<std::mutex> lk(mMtx);
    for (auto& pipeline : mLoadedPipeline) {
        if (!pipeline.empty()) return true;
    }
    return false;
}

bool eBPFServer::EnablePlugin(const std::string& pipeline_name, uint32_t plugin_index,
                        nami::PluginType type, 
                        const PipelineContext* ctx, 
                        const std::variant<SecurityOptions*, nami::ObserverNetworkOption*> options) {
    if (!IsSupportedEnv(type)) {
        return false;
    }
    return StartPluginInternal(pipeline_name, plugin_index, type, ctx, options);
}

bool eBPFServer::DisablePlugin(const std::string& pipeline_name, nami::PluginType type) {
    if (!IsSupportedEnv(type)) {
        return true;
    }
    std::string prev_pipeline = CheckLoadedPipelineName(type);
    if (prev_pipeline == pipeline_name) {
        UpdatePipelineName(type, "");
    } else {
        LOG_WARNING(sLogger, ("prev pipeline", prev_pipeline)("curr pipeline", pipeline_name));
        return true;
    }
    if (type == nami::PluginType::NETWORK_OBSERVE) {
        mGenerateFlag = false;
        if (mMetricMockThread.joinable()) mMetricMockThread.join();
    }
    bool ret = mSourceManager->StopPlugin(type);
    // UpdateContext must after than StopPlugin
    if (ret) UpdateCBContext(type, nullptr, -1, -1);
    return ret;
}

std::string eBPFServer::CheckLoadedPipelineName(nami::PluginType type) {
    std::lock_guard<std::mutex> lk(mMtx);
    return mLoadedPipeline[int(type)];
}

void eBPFServer::UpdatePipelineName(nami::PluginType type, const std::string& name) {
    std::lock_guard<std::mutex> lk(mMtx);
    mLoadedPipeline[int(type)] = name;
    return;
}

bool eBPFServer::SuspendPlugin(const std::string& pipeline_name, nami::PluginType type) {
    if (!IsSupportedEnv(type)) {
        return false;
    }
    // mark plugin status is update
    bool ret = mSourceManager->SuspendPlugin(type);
    if (ret) UpdateCBContext(type, nullptr, -1, -1);
    return ret;
}

void eBPFServer::UpdateCBContext(nami::PluginType type, const logtail::PipelineContext* ctx, logtail::QueueKey key, int idx) {
    switch (type) {
    case nami::PluginType::PROCESS_SECURITY:{
        if (mProcessSecureCB) mProcessSecureCB->UpdateContext(ctx, key, idx);
        return;
    }
    case nami::PluginType::NETWORK_OBSERVE:{
        if (mMeterCB) mMeterCB->UpdateContext(ctx, key, idx);
        if (mSpanCB) mSpanCB->UpdateContext(ctx, key, idx);
        if (mEventCB) mEventCB->UpdateContext(ctx, key, idx);
        return;
    }
    case nami::PluginType::NETWORK_SECURITY:{
        if (mNetworkSecureCB) mNetworkSecureCB->UpdateContext(ctx, key, idx);
        return;
    }
    case nami::PluginType::FILE_SECURITY:{
        if (mFileSecureCB) mFileSecureCB->UpdateContext(ctx, key, idx);
        return;
    }
    default:
        return;
    }
}

} // namespace ebpf
}
