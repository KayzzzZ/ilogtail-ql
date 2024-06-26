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

#include "ebpf/observer/ObserverServer.h"
#include "models/MetricEvent.h"
#include "models/PipelineEventGroup.h"
#include "models/PipelineEvent.h"
#include "logger/Logger.h"
#include "queue/ProcessQueueManager.h"
#include "queue/ProcessQueueItem.h"

#include <thread>
#include <vector>
#include <iostream>
#include <string>
#include <chrono>


namespace logtail {

// 负责接收ebpf返回的数据，然后将数据推送到对应的队列中
// TODO: 目前暂时没有考虑并发Start的问题
void ObserverServer::Start() {
    if (mIsRunning) {
        return;
    } else {
        mIsRunning = false;
        mock_thread_ = std::thread(&ObserverServer::MetricGenerator, this);
        // TODO: 创建一个线程，用于接收ebpf返回的数据，并将数据推送到对应的队列中
        LOG_INFO(sLogger, ("observer ebpf server", "started"));
    }
}

void ObserverServer::Stop() {
    // TODO: ebpf_stop(); 停止所有类型的ebpf探针
    mIsRunning = false;
}

// 插件配置注册逻辑
// 负责启动对应的ebpf程序
void ObserverServer::AddObserverOptions(const std::string& name,
                                        size_t index,
                                        ObserverOptions* options,
                                        PipelineContext* ctx) {
    std::string key = name + "#" + std::to_string(index);
    mInputConfigMap[key] = std::make_pair(options, ctx);
    // TODO: 目前一种类型的input只能处理一个，后续需要修改
    switch (options->mType) {
        case ObserverType::FILE: {
            // TODO: ebpf_start(type);
            file_ctx_ = ctx;
            break;
        }
        case ObserverType::PROCESS: {
            // TODO: ebpf_start(type);
            process_ctx_ = ctx;
            break;
        }
        case ObserverType::NETWORK: {
            // TODO: ebpf_start(type);
            network_ctx_ = ctx;
            break;
        }
        default:
            break;
    }
}

// 插件配置注销逻辑
// TODO: 目前处理配置变更，先stop掉该类型的探针，然后在map里remove配置
void ObserverServer::RemoveObserverOptions(const std::string& name, size_t index) {
    std::string key = name + "#" + std::to_string(index);
    // TODO: 目前一种类型的input只能处理一个，后续需要修改
    switch (mInputConfigMap[key].first->mType) {
        case ObserverType::FILE: {
            // TODO: ebpf_stop(type);
            break;
        }
        case ObserverType::PROCESS: {
            // TODO: ebpf_stop(type);
            break;
        }
        case ObserverType::NETWORK: {
            // TODO: ebpf_stop(type);
            break;
        }
        default:
            break;
    }
    mInputConfigMap.erase(key);
}

void ObserverServer::MetricGenerator() {
    std::cout << "[ObserverServer] enter metric generator" << std::endl;

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
    while (true) {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        int64_t current_time_millis = static_cast<int64_t>(millis);
        std::vector<std::unique_ptr<ProcessQueueItem>> items;
        // construct vector<PipelineEventGroup>
        // 1000 timeseries for app
        std::vector<std::string> app_ids = {"eeeb8df999f59f569da84d27fa408a94", "deddf8ef215107d8fd37540ac4e3291b", "52abe1564d8ee3fea66e9302fc21d80d", "87f79be5ab74d72b4a10b62c02dc7f34", "1796627f8e0b7fbba042c145820311f9"};
        for (int i = 0; i < app_ids.size(); i ++) {
            std::shared_ptr<SourceBuffer> mSourceBuffer = std::make_shared<SourceBuffer>();;
            PipelineEventGroup mTestEventGroup(mSourceBuffer);
            mTestEventGroup.SetTag(std::string("pid"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("appId"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("source_ip"), "10.54.0.55");
            for (int j = 0 ; j < app_metric_names.size(); j ++) {
                for (int z = 0; z < 1000; z ++ ) {
                    auto metricsEvent = mTestEventGroup.AddMetricEvent();
                    metricsEvent->SetTag(std::string("workloadName"), std::string("arms-oneagent-test-ql"));
                    metricsEvent->SetTag(std::string("workloadKind"), std::string("faceless"));
                    metricsEvent->SetTag(std::string("source_ip"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("host"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("rpc"), std::string("/oneagent/qianlu/local" + std::to_string(z)));
                    metricsEvent->SetTag(std::string("rpcType"), std::string("0"));
                    metricsEvent->SetTag(std::string("callType"), std::string("http"));
                    metricsEvent->SetTag(std::string("appType"), std::string("EBPF"));
                    metricsEvent->SetTag(std::string("statusCode"), std::string("200"));
                    metricsEvent->SetTag(std::string("version"), std::string("HTTP1.1"));
                    metricsEvent->SetTag(std::string("source"), std::string("ebpf"));
                    metricsEvent->SetName(app_metric_names[j]);
                    metricsEvent->SetValue(UntypedSingleValue{10.0});
                    metricsEvent->SetTimestamp(current_time_millis);
                }
            }

            std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(mTestEventGroup), 0);
            items.emplace_back(std::move(item));
        }

        // tcp_metrics
        for (int i = 0; i < app_ids.size(); i ++)  {
            std::shared_ptr<SourceBuffer> mSourceBuffer = std::make_shared<SourceBuffer>();;
            PipelineEventGroup mTestEventGroup(mSourceBuffer);
            mTestEventGroup.SetTag(std::string("pid"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("appId"), std::string(app_ids[i]));
            mTestEventGroup.SetTag(std::string("source_ip"), "10.54.0.44");
            for (int j = 0 ; j < tcp_metrics_names.size(); j ++) {
                for (int z = 0; z < 1000; z ++ ) {
                    auto metricsEvent = mTestEventGroup.AddMetricEvent();
                    metricsEvent->SetName(tcp_metrics_names[j]);
                    metricsEvent->SetTag(std::string("workloadName"), std::string("arms-oneagent-test-ql"));
                    metricsEvent->SetTag(std::string("workloadKind"), std::string("qianlu"));
                    metricsEvent->SetTag(std::string("source_ip"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("host"), std::string("10.54.0.33"));
                    metricsEvent->SetTag(std::string("dest_ip"), std::string("10.54.0." + std::to_string(z)));
                    metricsEvent->SetTag(std::string("callType"), std::string("conn_stats"));
                    metricsEvent->SetTag(std::string("appType"), std::string("EBPF"));
                    metricsEvent->SetValue(UntypedSingleValue{20.0});
                    metricsEvent->SetTimestamp(current_time_millis);
                }
            }

            std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(mTestEventGroup), 0);
            items.emplace_back(std::move(item));
        }


        // push vector<PipelineEventGroup>
        for (int i = 0; i < items.size(); i ++) {
            auto status =ProcessQueueManager::GetInstance()->PushQueue(process_ctx_->GetProcessQueueKey(), std::move(items[i]));
            if (status) {
                LOG_WARNING(sLogger, ("[Metrics] push queue failed!", "a"));
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
    std::cout << "[Observer] exit metrics generator" << std::endl;
}

} // namespace logtail
