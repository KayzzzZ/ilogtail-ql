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

#include "ebpf/security/SecurityServer.h"
#include "models/SpanEvent.h"
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
#include <random>


namespace logtail {

// 负责接收ebpf返回的数据，然后将数据推送到对应的队列中
// TODO: 目前暂时没有考虑并发Start的问题
void SecurityServer::Start() {
    if (mIsRunning) {
        return;
    } else {
        mock_thread_ = std::thread(&SecurityServer::SpanGenerator, this);
        mIsRunning = true;
        // TODO: 创建一个线程，用于接收ebpf返回的数据，并将数据推送到对应的队列中
        LOG_INFO(sLogger, ("security ebpf server", "started"));
    }
}

void SecurityServer::Stop() {
    // TODO: ebpf_stop(); 停止所有类型的ebpf探针
    mIsRunning = false;
}

// 插件配置注册逻辑
// 负责启动对应的ebpf程序
void SecurityServer::AddSecurityOptions(const std::string& name,
                                        size_t index,
                                        SecurityOptions* options,
                                        PipelineContext* ctx) {
    std::string key = name + "#" + std::to_string(index);
    mInputConfigMap[key] = std::make_pair(options, ctx);
    // TODO: 目前一种类型的input只能处理一个，后续需要修改
    switch (options->mFilterType) {
        case SecurityFilterType::FILE: {
            // TODO: ebpf_start(type);
            file_ctx_ = ctx;
            break;
        }
        case SecurityFilterType::PROCESS: {
            // TODO: ebpf_start(type);
            process_ctx_ = ctx;
            break;
        }
        case SecurityFilterType::NETWORK: {
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
void SecurityServer::RemoveSecurityOptions(const std::string& name, size_t index) {
    std::string key = name + "#" + std::to_string(index);
    // TODO: 目前一种类型的input只能处理一个，后续需要修改
    switch (mInputConfigMap[key].first->mFilterType) {
        case SecurityFilterType::FILE: {
            // TODO: ebpf_stop(type);
            break;
        }
        case SecurityFilterType::PROCESS: {
            // TODO: ebpf_stop(type);
            break;
        }
        case SecurityFilterType::NETWORK: {
            // TODO: ebpf_stop(type);
            break;
        }
        default:
            break;
    }
    mInputConfigMap.erase(key);
}

std::string SecurityServer::generateRandomString(size_t length) {
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

void SecurityServer::SpanGenerator() {
    std::cout << "[SecurityServer] enter span generator" << std::endl;
    while (true) {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto nano = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
        uint64_t current_time_nano = static_cast<uint64_t>(nano);
        uint64_t end_time_nano = static_cast<uint64_t>(nano) + 100000;
        std::vector<std::unique_ptr<ProcessQueueItem>> items;
        // construct vector<PipelineEventGroup>
        // 1000 timeseries for app
        const std::vector<std::string> app_ids = {
                            "awy7aw18hz@72e78405b0019f2", 
                            // "awy7aw18hz@28e68435b9dc91e", 
                            // "awy7aw18hz@7e393063f3fd6ad", 
                            // "awy7aw18hz@431561339015065", 
                            // "awy7aw18hz@55d223739e51517",
                            // "awy7aw18hz@fa1f295a160f084",
                            // "awy7aw18hz@17dbf838fc39ade",
                        };
        for (int i = 0; i < app_ids.size(); i ++) {
            std::shared_ptr<SourceBuffer> mSourceBuffer = std::make_shared<SourceBuffer>();;
            PipelineEventGroup mTestEventGroup(mSourceBuffer);
            mTestEventGroup.SetTag("arms.appId", app_ids[i]);
            for (int j = 0; j < 100; j ++) {
                auto spanEvent = mTestEventGroup.AddSpanEvent();
                spanEvent->SetTag(std::string("workloadName"), "arms-oneagent-test-ql-" + std::to_string(i));
                spanEvent->SetTag(std::string("workloadKind"), std::string("Deployment"));
                spanEvent->SetTag(std::string("pid"), std::string("1d15aab965811c49f42019136da3958b"));
                spanEvent->SetTag(std::string("appId"), app_ids[i]);
                spanEvent->SetTag(std::string("source_ip"), std::string("10.54.0.33"));
                spanEvent->SetTag(std::string("host"), std::string("10.54.0.33"));
                spanEvent->SetTag(std::string("rpc"), std::string("/oneagent/lurious/local" + std::to_string(j)));
                spanEvent->SetTag(std::string("rpcType"), std::string("0"));
                spanEvent->SetTag(std::string("callType"), std::string("http"));
                spanEvent->SetTag(std::string("appType"), std::string("EBPF"));
                spanEvent->SetTag(std::string("statusCode"), std::string("200"));
                spanEvent->SetTag(std::string("version"), std::string("HTTP1.1"));
                spanEvent->SetTag(std::string("source"), std::string("ebpf"));
                spanEvent->SetTag(std::string("app"), std::string("mall-client-demo"));
                // set traceid etc
                spanEvent->SetName("/final-ql-faceless" + std::to_string(i));
                spanEvent->SetKind(SpanEvent::Kind::Client);
                spanEvent->SetStartTimeNs(current_time_nano);
                spanEvent->SetEndTimeNs(end_time_nano);
                std::string trace_id = generateRandomString(32);
                std::string span_id = generateRandomString(16);
                spanEvent->SetTraceId(trace_id);
                spanEvent->SetSpanId(span_id);
            }

            std::unique_ptr<ProcessQueueItem> item = std::make_unique<ProcessQueueItem>(std::move(mTestEventGroup), 0);
            if (ProcessQueueManager::GetInstance()->PushQueue(process_ctx_->GetProcessQueueKey(), std::move(item))) {
                LOG_WARNING(sLogger, ("[Span] push queue failed!", "a"));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "[SecurityServer] exit span generator" << std::endl;
}

} // namespace logtail
