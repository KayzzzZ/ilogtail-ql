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

#include "ebpf/eBPFServer.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include <random>

#include "app_config/AppConfig.h"
#include "common/Flags.h"
#include "common/Lock.h"
#include "common/LogtailCommonFlags.h"
#include "common/MachineInfoUtil.h"
#include "ebpf/Config.h"
#include "ebpf/include/export.h"
#include "logger/Logger.h"
#include "monitor/metric_models/ReentrantMetricsRecord.h"
#include "plugin/network_observer/NetworkObserverManager.h"
#include "metadata/K8sMetadata.h"


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

bool EnvManager::IsSupportedEnv(logtail::ebpf::PluginType type) {
    if (!mInited) {
        LOG_ERROR(sLogger, ("env manager not inited ...", ""));
        return false;
    }
    bool status = false;
    switch (type) {
        case logtail::ebpf::PluginType::NETWORK_OBSERVE:
            status = mArchSupport && (mBTFSupport || m310Support);
            break;
        case logtail::ebpf::PluginType::FILE_SECURITY:
        case logtail::ebpf::PluginType::NETWORK_SECURITY:
        case logtail::ebpf::PluginType::PROCESS_SECURITY: {
            status = mArchSupport && mBTFSupport;
            break;
        }
        default:
            status = false;
    }
    if (!status) {
        LOG_WARNING(sLogger,
                    ("runtime env not supported, plugin type: ", int(type))("arch support is ", mArchSupport)(
                        "btf support is ", mBTFSupport)("310 support is ", m310Support));
    }
    return status;
}

bool EnvManager::AbleToLoadDyLib() {
    return mArchSupport;
}

void EnvManager::InitEnvInfo() {
    if (mInited)
        return;
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
    LOG_INFO(sLogger, ("ebpf kernel release", release)("kernel version", version));
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
        LOG_WARNING(sLogger, ("unsupported kernel version, will not start eBPF plugin ... version", version));
        m310Support = false;
        return;
    }

    std::string os;
    int64_t osVersion;
    if (GetRedHatReleaseInfo(os, osVersion, STRING_FLAG(default_container_host_path))
        || GetRedHatReleaseInfo(os, osVersion)) {
        if (os == KERNEL_NAME_CENTOS && osVersion >= KERNEL_CENTOS_MIN_VERSION) {
            m310Support = true;
            return;
        } else {
            LOG_WARNING(
                sLogger,
                ("unsupported os for 310 kernel, will not start eBPF plugin ...", "")("os", os)("version", osVersion));
            m310Support = false;
            return;
        }
    }
    LOG_WARNING(sLogger, ("not redhat release, will not start eBPF plugin ...", ""));
    m310Support = false;
}

bool eBPFServer::IsSupportedEnv(logtail::ebpf::PluginType type) {
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
    // check env

    // mMonitorMgr = std::make_unique<eBPFSelfMonitorMgr>();
    DynamicMetricLabels dynamicLabels;
    dynamicLabels.emplace_back(METRIC_LABEL_KEY_PROJECT, [this]() -> std::string { return this->GetAllProjects(); });
    WriteMetrics::GetInstance()->PrepareMetricsRecordRef(
        mRef,
        MetricCategory::METRIC_CATEGORY_RUNNER,
        {{METRIC_LABEL_KEY_RUNNER_NAME, METRIC_LABEL_VALUE_RUNNER_NAME_EBPF_SERVER}},
        std::move(dynamicLabels));

    mStartPluginTotal = mRef.CreateCounter(METRIC_RUNNER_EBPF_START_PLUGIN_TOTAL);
    mStopPluginTotal = mRef.CreateCounter(METRIC_RUNNER_EBPF_STOP_PLUGIN_TOTAL);
    mSuspendPluginTotal = mRef.CreateCounter(METRIC_RUNNER_EBPF_SUSPEND_PLUGIN_TOTAL);

    mSourceManager = std::make_shared<SourceManager>();
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
    if (!mInited)
        return;
    mInited = false;
    LOG_INFO(sLogger, ("begin to stop all plugins", ""));
    // destroy source manager
    // do not destroy source manager ...
    // mSourceManager.reset();
    for (int i = 0; i < int(logtail::ebpf::PluginType::MAX); i++) {
        UpdatePipelineName(static_cast<logtail::ebpf::PluginType>(i), "", "");
    }

    // UpdateContext must after than StopPlugin
    if (mEventCB)
        mEventCB->UpdateContext(nullptr, -1, -1);
    if (mMeterCB)
        mMeterCB->UpdateContext(nullptr, -1, -1);
    if (mSpanCB)
        mSpanCB->UpdateContext(nullptr, -1, -1);
    if (mNetworkSecureCB)
        mNetworkSecureCB->UpdateContext(nullptr, -1, -1);
    if (mProcessSecureCB)
        mProcessSecureCB->UpdateContext(nullptr, -1, -1);
    if (mFileSecureCB)
        mFileSecureCB->UpdateContext(nullptr, -1, -1);
}

// maybe update or create 
bool eBPFServer::StartPluginInternal(const std::string& pipeline_name,
                                     uint32_t plugin_index,
                                     logtail::ebpf::PluginType type,
                                     const logtail::PipelineContext* ctx,
                                     const std::variant<SecurityOptions*, logtail::ebpf::ObserverNetworkOption*> options,
                                     PluginMetricManagerPtr mgr) {
    std::string prev_pipeline_name = CheckLoadedPipelineName(type);
    if (prev_pipeline_name.size() && prev_pipeline_name != pipeline_name) {
        LOG_WARNING(sLogger,
                    ("pipeline already loaded, plugin type",
                     int(type))("prev pipeline", prev_pipeline_name)("curr pipeline", pipeline_name));
        return false;
    }

    UpdatePipelineName(type, pipeline_name, ctx->GetProjectName());

    // init self monitor
    // mMonitorMgr->Init(type, mgr, pipeline_name, ctx->GetProjectName());

    // step1: convert options to export type
    bool ret = false;
    auto eBPFConfig = std::make_unique<logtail::ebpf::PluginConfig>();
    eBPFConfig->mPluginType = type;
    // call update function
    // step2: call init function
    switch (type) {
        case logtail::ebpf::PluginType::PROCESS_SECURITY: {
            logtail::ebpf::ProcessConfig pconfig;
            // TODO @qianlu.kk set new handler ...

            // pconfig.process_security_cb_ = [this](std::vector<std::unique_ptr<AbstractSecurityEvent>>& events) {
            //     return mProcessSecureCB->handle(events);
            // };
            SecurityOptions* opts = std::get<SecurityOptions*>(options);
            pconfig.options_ = opts->mOptionList;
            // UpdateContext must ahead of StartPlugin
            mProcessSecureCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
            eBPFConfig->mConfig = std::move(pconfig);
            ret = mSourceManager->StartPlugin(type, std::move(eBPFConfig));
            break;
        }

        case logtail::ebpf::PluginType::NETWORK_OBSERVE: {
            logtail::ebpf::NetworkObserveConfig nconfig;

            auto opts = std::get<ObserverNetworkOption*>(options);
            if (opts) {
                mGenerateFlag = true;
                if (opts->mEnableMetric) {
                    mMeterCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
                    mMetricMockThread = std::thread(&eBPFServer::GenerateMetric, this, ctx->GetProcessQueueKey(), plugin_index);
                }
                if (opts->mEnableSpan) {
                    mSpanCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
                    mTraceMockThread = std::thread(&eBPFServer::GenerateSpan, this, ctx->GetProcessQueueKey(), plugin_index);
                }
                if (opts->mEnableLog) {
                    mEventCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
                    mLogMockThread = std::thread(&eBPFServer::GenerateAgentInfo, this, ctx->GetProcessQueueKey(), plugin_index);
                }
            }
            // TODO @qianlu.kk register k8s metadata callback for metric ??
            
            
            mEventCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
            auto idx = static_cast<int>(PluginType::NETWORK_OBSERVE);
            mPlugins[idx] = NetworkObserverManager::Create(
                mBaseManager, 
                mSourceManager, 
                [&](const std::vector<std::unique_ptr<ApplicationBatchEvent>>& events) {
                    mEventCB->handle(events);
                }
            );

            ret = (mPlugins[idx]->Init(options) == 0);
            break;
        }

        case logtail::ebpf::PluginType::NETWORK_SECURITY: {
            logtail::ebpf::NetworkSecurityConfig nconfig;
            // TODO @qianlu.kk set new handler ...

            // nconfig.network_security_cb_ = [this](std::vector<std::unique_ptr<AbstractSecurityEvent>>& events) {
            //     return mNetworkSecureCB->handle(events);
            // };
            // SecurityOptions* opts = std::get<SecurityOptions*>(options);
            // nconfig.options_ = opts->mOptionList;
            // eBPFConfig->mConfig = std::move(nconfig);
            // // UpdateContext must ahead of StartPlugin
            // mNetworkSecureCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
            // ret = mSourceManager->StartPlugin(type, std::move(eBPFConfig));
            break;
        }

        case logtail::ebpf::PluginType::FILE_SECURITY: {
            logtail::ebpf::FileSecurityConfig fconfig;
            // TODO @qianlu.kk set new handler ...

            // fconfig.file_security_cb_ = [this](std::vector<std::unique_ptr<AbstractSecurityEvent>>& events) {
            //     return mFileSecureCB->handle(events);
            // };
            // SecurityOptions* opts = std::get<SecurityOptions*>(options);
            // fconfig.options_ = opts->mOptionList;
            // eBPFConfig->mConfig = std::move(fconfig);
            // // UpdateContext must ahead of StartPlugin
            // mFileSecureCB->UpdateContext(ctx, ctx->GetProcessQueueKey(), plugin_index);
            // ret = mSourceManager->StartPlugin(type, std::move(eBPFConfig));
            break;
        }
        default:
            LOG_ERROR(sLogger, ("unknown plugin type", int(type)));
            return false;
    }

    if (ret) {
        mStartPluginTotal->Add(1);
    }

    return ret;
}

bool eBPFServer::HasRegisteredPlugins() const {
    std::lock_guard<std::mutex> lk(mMtx);
    for (auto& pipeline : mLoadedPipeline) {
        if (!pipeline.empty())
            return true;
    }
    return false;
}

bool eBPFServer::EnablePlugin(const std::string& pipeline_name,
                              uint32_t plugin_index,
                              logtail::ebpf::PluginType type,
                              const PipelineContext* ctx,
                              const std::variant<SecurityOptions*, logtail::ebpf::ObserverNetworkOption*> options,
                              PluginMetricManagerPtr mgr) {
    if (!IsSupportedEnv(type)) {
        return false;
    }
    return StartPluginInternal(pipeline_name, plugin_index, type, ctx, options, mgr);
}

bool eBPFServer::DisablePlugin(const std::string& pipeline_name, logtail::ebpf::PluginType type) {
    if (!IsSupportedEnv(type)) {
        return true;
    }
    std::string prev_pipeline = CheckLoadedPipelineName(type);
    if (prev_pipeline == pipeline_name) {
        UpdatePipelineName(type, "", "");
    } else {
        LOG_WARNING(sLogger, ("prev pipeline", prev_pipeline)("curr pipeline", pipeline_name));
        return true;
    }
    bool ret = mSourceManager->StopPlugin(type);
    // UpdateContext must after than StopPlugin
    if (ret) {
        UpdateCBContext(type, nullptr, -1, -1);
        mStopPluginTotal->Add(1);
    }
    return ret;
}

std::string eBPFServer::CheckLoadedPipelineName(logtail::ebpf::PluginType type) {
    std::lock_guard<std::mutex> lk(mMtx);
    return mLoadedPipeline[int(type)];
}

std::string eBPFServer::GetAllProjects() {
    std::lock_guard<std::mutex> lk(mMtx);
    std::string res;
    for (int i = 0; i < int(logtail::ebpf::PluginType::MAX); i++) {
        if (mPluginProject[i] != "") {
            res += mPluginProject[i];
            res += " ";
        }
    }
    return res;
}

void eBPFServer::UpdatePipelineName(logtail::ebpf::PluginType type, const std::string& name, const std::string& project) {
    std::lock_guard<std::mutex> lk(mMtx);
    mLoadedPipeline[int(type)] = name;
    mPluginProject[int(type)] = project;
    return;
}

bool eBPFServer::SuspendPlugin(const std::string& pipeline_name, logtail::ebpf::PluginType type) {
    if (!IsSupportedEnv(type)) {
        return false;
    }
    // mark plugin status is update
    bool ret = mSourceManager->SuspendPlugin(type);
    if (ret) {
        UpdateCBContext(type, nullptr, -1, -1);
        mSuspendPluginTotal->Add(1);
    }
    return ret;
}

void eBPFServer::UpdateCBContext(logtail::ebpf::PluginType type,
                                 const logtail::PipelineContext* ctx,
                                 logtail::QueueKey key,
                                 int idx) {
    switch (type) {
        case logtail::ebpf::PluginType::PROCESS_SECURITY: {
            if (mProcessSecureCB)
                mProcessSecureCB->UpdateContext(ctx, key, idx);
            return;
        }
        case logtail::ebpf::PluginType::NETWORK_OBSERVE: {
            if (mMeterCB)
                mMeterCB->UpdateContext(ctx, key, idx);
            if (mSpanCB)
                mSpanCB->UpdateContext(ctx, key, idx);
            if (mEventCB)
                mEventCB->UpdateContext(ctx, key, idx);
            return;
        }
        case logtail::ebpf::PluginType::NETWORK_SECURITY: {
            if (mNetworkSecureCB)
                mNetworkSecureCB->UpdateContext(ctx, key, idx);
            return;
        }
        case logtail::ebpf::PluginType::FILE_SECURITY: {
            if (mFileSecureCB)
                mFileSecureCB->UpdateContext(ctx, key, idx);
            return;
        }
        default:
            return;
    }
}

/// ********


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
            "6424c56cdaa1e5639d298e858c92d107", 
            // "deddf8ef215107d8fd37540ac4e3291b", 
            // "52abe1564d8ee3fea66e9302fc21d80d", 
            // "87f79be5ab74d72b4a10b62c02dc7f34", 
            // "1796627f8e0b7fbba042c145820311f9"
        };
        std::vector<std::string> app_names = {
            "ql-test-cp", 
            // "test-service-2", 
            // "test-service-3", 
            // "test-service-4", 
            // "test-service-5"
        };

        for (size_t i = 0; i < app_ids.size(); i ++) {
            std::shared_ptr<SourceBuffer> mSourceBuffer = std::make_shared<SourceBuffer>();;
            PipelineEventGroup mTestEventGroup(mSourceBuffer);
            mTestEventGroup.SetTag(std::string("pid"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("serverIp"), "10.28.197.177");
            mTestEventGroup.SetTag(std::string("source"), std::string("ebpf"));
            mTestEventGroup.SetTag(std::string("service"), app_names[i]);
            mTestEventGroup.SetTag(std::string("data_type"), std::string("metric"));

            // set tag entity
            auto* evt = mTestEventGroup.AddMetricEvent();
            evt->SetTag(std::string("agentVersion"), std::string("v1"));
            evt->SetTag(std::string("app"), app_names[i]); // workloadname
            evt->SetTag(std::string("resourceid"), app_ids[i]);
            evt->SetTag(std::string("resourcetype"), std::string("APPLICATION"));
            evt->SetTag(std::string("version"), std::string("v1"));
            evt->SetTag(std::string("clusterId"), std::string("c0748d004a7ce431d8da62ed8f6134879"));
            evt->SetTag(std::string("host"), std::string("10.28.197.177"));
            evt->SetTag(std::string("hostname"), std::string("continuous-profiling-5d7b7fd458-tkn2n"));
            evt->SetTag(std::string("namespace"), std::string("arms-apm-demo"));
            evt->SetTag(std::string("workloadKind"), std::string("Deployment"));
            evt->SetTag(std::string("workloadName"), std::string("continuous-profiling"));
            evt->SetName("arms_tag_entity");
            evt->SetValue(UntypedSingleValue{1.0});
            evt->SetTimestamp(seconds, 0);

            for (size_t j = 0 ; j < app_metric_names.size(); j ++) {
                for (size_t z = 0; z < 25; z ++ ) {
                    if (app_metric_names[j] == "arms_rpc_requests_error_count") {
                        if (z % 5) {
                            continue;
                        }
                    }
                    if (app_metric_names[j] == "arms_rpc_requests_slow_count") {
                        if (z % 4) {
                            continue;
                        }
                    }
                    auto metricsEvent = mTestEventGroup.AddMetricEvent();
                    metricsEvent->SetTag(std::string("workloadName"), std::string("continuous-profiling"));
                    metricsEvent->SetTag(std::string("workloadKind"), std::string("Deployment"));
                    // metricsEvent->SetTag(std::string("source_ip"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("host"), std::string("continuous-profiling-5d7b7fd458-tkn2n"));
                    metricsEvent->SetTag(std::string("rpc"), std::string("/oneagent/qianlu/local/20250113/" + std::to_string(z)));
                    metricsEvent->SetTag(std::string("rpcType"), std::string("0"));
                    metricsEvent->SetTag(std::string("callType"), std::string("http"));
                    metricsEvent->SetTag(std::string("callKind"), std::string("http"));
                    metricsEvent->SetTag(std::string("status"), std::string("200"));
                    metricsEvent->SetTag(std::string("version"), std::string("HTTP1.1"));
                    metricsEvent->SetName(app_metric_names[j]);
                    metricsEvent->SetValue(UntypedSingleValue{10.0});
                    
                    if (app_metric_names[j] == "arms_rpc_requests_seconds") {
                        if (z % 4) {
                            metricsEvent->SetValue(UntypedSingleValue{0.2});
                        } else {
                            metricsEvent->SetValue(UntypedSingleValue{2});
                        }
                        
                    } else {
                        metricsEvent->SetValue(UntypedSingleValue{10.0});
                    }
                    metricsEvent->SetTimestamp(seconds, 0);
                }
                // for client metric
                auto clientMetric = mTestEventGroup.AddMetricEvent();
                clientMetric->SetTag(std::string("workloadName"), std::string("continuous-profiling"));
                clientMetric->SetTag(std::string("workloadKind"), std::string("Deployment"));
                clientMetric->SetTag(std::string("host"), std::string("continuous-profiling-5d7b7fd458-tkn2n"));
                clientMetric->SetTag(std::string("rpc"), std::string("/mysql/exec"));
                clientMetric->SetTag(std::string("rpcType"), std::string("25"));
                clientMetric->SetTag(std::string("callType"), std::string("http_client"));
                clientMetric->SetTag(std::string("callKind"), std::string("http_client"));
                clientMetric->SetTag(std::string("status"), std::string("200"));
                clientMetric->SetTag(std::string("version"), std::string("HTTP1.1"));
                clientMetric->SetTag(std::string("destId"), std::string("10.28.197.190")); // ip
                clientMetric->SetTag(std::string("endpoint"), std::string("/mysql/exec"));
                clientMetric->SetName(app_metric_names[j]);
                clientMetric->SetValue(UntypedSingleValue{10.0});
                clientMetric->SetTimestamp(seconds, 0);
            }
            std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(mTestEventGroup), idx);
            items.emplace_back(std::move(item));
        }
        // tcp_metrics
        for (size_t i = 0; i < app_ids.size(); i ++)  {
            std::shared_ptr<SourceBuffer> mSourceBuffer = std::make_shared<SourceBuffer>();;
            PipelineEventGroup mTestEventGroup(mSourceBuffer);
            mTestEventGroup.SetTag(std::string("pid"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("serverIp"), "10.28.197.177");
            mTestEventGroup.SetTag(std::string("source"), std::string("ebpf"));
            mTestEventGroup.SetTag(std::string("service"), app_names[i]);
            mTestEventGroup.SetTag(std::string("data_type"), std::string("metric"));
            for (size_t j = 0 ; j < tcp_metrics_names.size(); j ++) {
                for (size_t z = 0; z < 20; z ++ ) {
                    auto metricsEvent = mTestEventGroup.AddMetricEvent();
                    metricsEvent->SetName(tcp_metrics_names[j]);
                    metricsEvent->SetTag(std::string("workloadName"), std::string("continuous-profiling"));
                    metricsEvent->SetTag(std::string("workloadKind"), std::string("Deployment"));
                    metricsEvent->SetTag(std::string("source_ip"), std::string("10.28.197.177"));
                    metricsEvent->SetTag(std::string("host"), std::string("continuous-profiling-5d7b7fd458-tkn2n"));
                    metricsEvent->SetTag(std::string("dest_ip"), std::string("10.54.0." + std::to_string(z)));
                    metricsEvent->SetTag(std::string("callType"), std::string("conn_stats"));
                    metricsEvent->SetValue(UntypedSingleValue{20.0});
                    metricsEvent->SetTimestamp(seconds, 0);
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

std::string GenerateRandomString(size_t length) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;  // 用于获取随机种子
    std::mt19937 generator(rd());  // 标准梅森旋转算法的随机数生成器
    std::uniform_int_distribution<> distribution(0, chars.size() - 1);
    std::string result;
    for (size_t i = 0; i < length; ++i) {
        result += chars[distribution(generator)];
    }
    return result;
}

void eBPFServer::GenerateSpan(logtail::QueueKey key, uint32_t idx) {
    LOG_INFO(sLogger, ("[ObserverServer] enter span generator", ""));
    // generate metrics
    while (mGenerateFlag) {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        auto nano = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
        std::vector<std::unique_ptr<ProcessQueueItem>> items;
        // construct vector<PipelineEventGroup>
        // 1000 timeseries for app
        std::vector<std::string> app_ids = {
            "6424c56cdaa1e5639d298e858c92d107", 
            // "deddf8ef215107d8fd37540ac4e3291b", 
            // "52abe1564d8ee3fea66e9302fc21d80d", 
            // "87f79be5ab74d72b4a10b62c02dc7f34", 
            // "1796627f8e0b7fbba042c145820311f9"
        };
        std::vector<std::string> service_name = {
            "ql-test-cp",
            // "test-service-2",
            // "test-service-3",
            // "test-service-4",
            // "test-service-5"
        };

        for (size_t i = 0; i < app_ids.size(); i ++) {
            std::shared_ptr<SourceBuffer> mSourceBuffer = std::make_shared<SourceBuffer>();;
            PipelineEventGroup mTestEventGroup(mSourceBuffer);
            mTestEventGroup.SetTag(std::string("service.name"), service_name[i]);
            mTestEventGroup.SetTag(std::string("arms.appId"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("host.ip"), "10.28.197.177");
            mTestEventGroup.SetTag(std::string("arms.app.type"), std::string("ebpf"));
            mTestEventGroup.SetTag(std::string("data_type"), std::string("trace"));
            for (size_t j = 0 ; j < 25; j ++) {
                auto spanEvent = mTestEventGroup.AddSpanEvent();
                // spanEvent->SetScopeTag();
                spanEvent->SetTag(std::string("workloadName"), std::string("continuous-profiling"));
                spanEvent->SetTag(std::string("workloadKind"), std::string("Deployment"));
                spanEvent->SetTag(std::string("source_ip"), std::string("10.28.197.177"));
                spanEvent->SetTag(std::string("host"), std::string("continuous-profiling-5d7b7fd458-tkn2n"));
                spanEvent->SetTag(std::string("rpc"), std::string("/oneagent/qianlu/local/20250113" + std::to_string(j)));
                spanEvent->SetTag(std::string("rpcType"), std::string("0"));
                spanEvent->SetTag(std::string("callType"), std::string("http"));
                spanEvent->SetTag(std::string("statusCode"), std::string("200"));
                spanEvent->SetTag(std::string("version"), std::string("HTTP1.1"));
                spanEvent->SetName("/oneagent/qianlu/local/20250113/" + std::to_string(j));
                spanEvent->SetKind(SpanEvent::Kind::Server);
                std::string trace_id = GenerateRandomString(32);
                std::string span_id = GenerateRandomString(16);
                spanEvent->SetSpanId(span_id);
                spanEvent->SetTraceId(trace_id);
                spanEvent->SetStartTimeNs(nano - 5e6);
                spanEvent->SetEndTimeNs(nano);

                spanEvent->SetTimestamp(seconds);
            }
            for (size_t j = 0 ; j < 25; j ++) {
                auto spanEvent = mTestEventGroup.AddSpanEvent();
                spanEvent->SetTag(std::string("workloadName"), std::string("continuous-profiling"));
                spanEvent->SetTag(std::string("workloadKind"), std::string("Deployment"));
                spanEvent->SetTag(std::string("source_ip"), std::string("10.28.197.177"));
                spanEvent->SetTag(std::string("host"), std::string("continuous-profiling-5d7b7fd458-tkn2n"));
                spanEvent->SetTag(std::string("rpc"), std::string("/oneagent/qianlu/local/20250113/" + std::to_string(j)));
                spanEvent->SetTag(std::string("rpcType"), std::string("25"));
                spanEvent->SetTag(std::string("callType"), std::string("http-client"));
                spanEvent->SetTag(std::string("statusCode"), std::string("200"));
                spanEvent->SetTag(std::string("version"), std::string("HTTP1.1"));
                spanEvent->SetName("/oneagent/qianlu/local/20250113/" + std::to_string(j));
                spanEvent->SetKind(SpanEvent::Kind::Client);
                std::string trace_id = GenerateRandomString(32);
                std::string span_id = GenerateRandomString(16);
                spanEvent->SetSpanId(span_id);
                spanEvent->SetTraceId(trace_id);
                spanEvent->SetStartTimeNs(nano - 5e9);
                spanEvent->SetEndTimeNs(nano);

                spanEvent->SetTimestamp(seconds);
            }
            std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(mTestEventGroup), idx);
            items.emplace_back(std::move(item));
        }
        // push vector<PipelineEventGroup>
        for (size_t i = 0; i < items.size(); i ++) {
            auto status =ProcessQueueManager::GetInstance()->PushQueue(key, std::move(items[i]));
            if (status) {
                LOG_WARNING(sLogger, ("[Span] push queue failed! status", status));
            } else {
                LOG_INFO(sLogger, ("[Span] push queue success!", ""));
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    LOG_INFO(sLogger, ("[Observer] exit span generator", ""));
}

void eBPFServer::GenerateAgentInfo(logtail::QueueKey key, uint32_t idx) {
    LOG_INFO(sLogger, ("[ObserverServer] enter agentinfo generator", ""));
    while(mGenerateFlag) {
        std::shared_ptr<SourceBuffer> sourceBuffer = std::make_shared<SourceBuffer>();
        PipelineEventGroup eventGroup(sourceBuffer);
        eventGroup.SetTag(std::string("data_type"), std::string("agent_info"));
        const std::string app_id_key = "pid";
        const std::string agentIdKey = "agentId";
        const std::string app_prefix = "app-";
        const std::string agent_version = "1.0.0-rc";
        const std::string vmVersion = "xxxx";
        const std::string startTimestamp = "1729479979167"; // ms
        const std::string startTimestampKey = "startTimeStamp";
        const std::string appNameKey = "appName";
        const std::string appNamePrefix = "test-ebpf-app-";
        const std::string ipKey = "ip";
        const std::string ip_prefix = "30.221.146.";

        const std::string agentVersionKey = "agentVersion";

        for (int i = 0; i < 1; i ++) {
            std::string app = "ql-test-cp";
            std::string ip = "10.28.197.177";
            auto logEvent = eventGroup.AddLogEvent();
            logEvent->SetContent(app_id_key, "6424c56cdaa1e5639d298e858c92d107");
            logEvent->SetContent(appNameKey, app);
            logEvent->SetContent(ipKey, ip);
            logEvent->SetContent(std::string("hostname"), std::string("continuous-profiling-5d7b7fd458-tkn2n"));
            logEvent->SetContent(startTimestampKey, startTimestamp);
            logEvent->SetContent(agentVersionKey, "0.0.1");
            logEvent->SetTimestamp(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        }
        std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(eventGroup), idx);
        auto res = ProcessQueueManager::GetInstance()->PushQueue(key, std::move(item));
        if (res) {
            LOG_WARNING(sLogger, ("[AgentInfo] push queue failed! status", res));
        } else {
            LOG_INFO(sLogger, ("[AgentInfo] push queue success!", ""));
        }
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
    LOG_INFO(sLogger, ("[Observer] exit agentinfo generator", ""));
}

// *********

} // namespace ebpf
} // namespace logtail
