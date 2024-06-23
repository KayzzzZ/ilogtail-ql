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
#include "queue/ProcessQueueManager.h"
#include "queue/ProcessQueueItem.h"

#include <thread>
#include <mutex>
#include <iostream>
#include <memory>
#include <chrono>

namespace logtail {

// 负责接收ebpf返回的数据，然后将数据推送到对应的队列中
// TODO: 目前暂时没有考虑并发Start的问题

// input 代码 + 联调安全
void SecurityServer::Start(BPFSecurityPipelineType type) {
    if (mIsRunning) {
        return;
    } else {
        // TODO: 创建一个线程，用于接收ebpf返回的数据，并将数据推送到对应的队列中
        Init();
        mIsRunning = true;
        LOG_INFO(sLogger, ("security ebpf server", "started"));
    }
}

void SecurityServer::Stop(BPFSecurityPipelineType type) {
    // TODO: ebpf_stop(); 停止所有类型的ebpf探针
    mIsRunning = false;
}

void SecurityServer::Stop() {
    // TODO: ebpf_stop(); 停止所有类型的ebpf探针
    mIsRunning = false;
}

// 插件配置注册逻辑
// 负责启动对应的ebpf程序
void SecurityServer::AddSecurityOptions(const std::string& name,
                                        size_t index,
                                        const SecurityOptions* options,
                                        const PipelineContext* ctx) {
    std::string key = name + "#" + std::to_string(index);
    mInputConfigMap[key] = std::make_pair(options, ctx);
    // TODO: 目前一种类型的input只能处理一个，后续需要修改
    switch (options->mFilterType) {
        case SecurityFilterType::FILE: {
            // TODO: ebpf_start(type);
            fileConfig_ = std::make_pair(options, ctx);
            break;
        }
        case SecurityFilterType::PROCESS: {
            // TODO: ebpf_start(type);
            processConfig_ = std::make_pair(options, ctx);
            break;
        }
        case SecurityFilterType::NETWORK: {
            // TODO: ebpf_start(type);
            networkConfig_ = std::make_pair(options, ctx);
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
            fileConfig_ = std::make_pair(nullptr, nullptr);
            break;
        }
        case SecurityFilterType::PROCESS: {
            // TODO: ebpf_stop(type);
            processConfig_ = std::make_pair(nullptr, nullptr);
            break;
        }
        case SecurityFilterType::NETWORK: {
            // TODO: ebpf_stop(type);
            networkConfig_ = std::make_pair(nullptr, nullptr);
            break;
        }
        default:
            break;
    }
    mInputConfigMap.erase(key);
}

void SecurityServer::Init() {
    std::call_once(once_, std::bind(&SecurityServer::InitBPF, this));
}

void SecurityServer::HandleProcessSecureEvent(std::unique_ptr<AbstractSecurityEvent> event) {
    if (event == nullptr) return;

    auto ctx = this->processConfig_.second;
    auto source_buffer = std::make_shared<SourceBuffer>();
    PipelineEventGroup group(source_buffer);
    auto log_event = group.AddLogEvent();
    auto tags = event->GetAllTags();
    for (auto tag : tags) {
        log_event->SetContent(tag.first, tag.second);
    }

    std::unique_ptr<ProcessQueueItem> item = 
            std::unique_ptr<ProcessQueueItem>(new ProcessQueueItem(std::move(group), 0));
    ProcessQueueManager::GetInstance()->PushQueue(ctx->GetProcessQueueKey(), std::move(item));

}

void SecurityServer::InitBPF() {
    sm_ = logtail::ebpf::source_manager();
    sm_.initPlugin("/usr/local/ilogtail/libsockettrace_secure.so", "");
    this->flag_ = true;
    core_thread_ = std::thread(&SecurityServer::CollectEvents, this);
}

void SecurityServer::StopBPF() {
    sm_.clearPlugin();
    this->flag_ = false;
    if (core_thread_.joinable()) {
        core_thread_.join();
    }
}

void SecurityServer::CollectEvents() {
    // std::unique_ptr<ProcessQueueItem> item
    //     = std::unique_ptr<ProcessQueueItem>(new ProcessQueueItem(std::move(group), inputIndex));
    // for (size_t i = 0; i < retryTimes; ++i) {
    //     if (ProcessQueueManager::GetInstance()->PushQueue(key, std::move(item)) == 0) {
    //         return true;
    //     }
    //     if (i % 100 == 0) {
    //         LOG_WARNING(sLogger,
    //                     ("push attempts to process queue continuously failed for the past second",
    //                      "retry again")("config", QueueKeyManager::GetInstance()->GetName(key))("input index",
    //                                                                                             ToString(inputIndex)));
    //     }
    //     std::this_thread::sleep_for(std::chrono::milliseconds(10));
    // }
    while (flag_) {
        if (this->processConfig_.second == nullptr) continue;

        auto ctx = this->processConfig_.second;
        auto source_buffer = std::make_shared<SourceBuffer>();
        PipelineEventGroup group(source_buffer);

        // for (int i = 0; i < 10; i ++ ) {
        //     auto event = group.AddLogEvent();
        //     event->SetContentNoCopy("qianlu", "test");
        //     event->SetContentNoCopy("key1", "value1");
        //     event->SetContentNoCopy("key2", "value2");
        //     event->SetContentNoCopy("key3", "value3");

        //     auto spanEvent = group.AddSpanEvent();
        // }
        std::unique_ptr<ProcessQueueItem> item = 
                std::unique_ptr<ProcessQueueItem>(new ProcessQueueItem(std::move(group), 0));
        ProcessQueueManager::GetInstance()->PushQueue(ctx->GetProcessQueueKey(), std::move(item));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // get ops and config
    // auto securityConfigMap = this->mInputConfigMap[0];
    // auto m_ctx = securityConfigMap.second;
    // auto key = m_ctx->GetProcessQueueKey();
    // auto item = std::make_unique<ProcessQueueItem>();
    // for (int i = 0 ; i < 1000; i ++ ) {
    //     auto event = item->mEventGroup.AddLogEvent();

    //     event->SetContent("aa", "aa");
    // }
    // ProcessQueueManager::GetInstance()->PushQueue(key, std::move(item));
}

} // namespace logtail
