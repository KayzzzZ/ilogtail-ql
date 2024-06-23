/*
 * Copyright 2023 iLogtail Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <string>
#include <unordered_map>
#include <utility>
#include <mutex>
#include <thread>
#include <memory>

#include "ebpf/security/SecurityOptions.h"
#include "pipeline/PipelineContext.h"
#include "ebpf/SourceManager.h"
#include "SecurityAPI.h"

namespace logtail {

enum class BPFSecurityPipelineType {
    UNKNOWN,
    PIPELINE_PROCESS,
    PIPELINE_NETWORK,
    PIPELINE_FILE,
    MAX,
};

class SecurityServer {
public:
    SecurityServer(const SecurityServer&) = delete;
    SecurityServer& operator=(const SecurityServer&) = delete;

    static SecurityServer* GetInstance() {
        static SecurityServer instance;
        return &instance;
    }

    void Start(BPFSecurityPipelineType);
    void Stop(BPFSecurityPipelineType);
    void Stop();

    // 其他函数注册：配置注册、注销等
    void AddSecurityOptions(const std::string& name,
                            size_t index,
                            const SecurityOptions* options,
                            const PipelineContext* ctx);
    void RemoveSecurityOptions(const std::string& name, size_t index);

private:
    SecurityServer() = default;
    ~SecurityServer() = default;

    void HandleSecureEvent(std::unique_ptr<AbstractSecurityEvent> event);

    void Init();
    void InitBPF();
    void StopBPF();
    void CollectEvents();

    bool mIsRunning = false;
    // TODO: 目前配置更新时，会停止ebpf探针、重新加载配置、重新启动ebpf探针，后续优化时需要考虑这里的并发问题
    std::unordered_map<std::string, SecurityConfig> mInputConfigMap;
    // std::unordered_map<pair<std::string, size_t>, const pointer*> mEbpfPointerMap;
    logtail::ebpf::source_manager sm_;
    std::once_flag once_;
    std::thread core_thread_;
    volatile int flag_;

    SecurityConfig networkConfig_;
    SecurityConfig processConfig_;
    SecurityConfig fileConfig_;
};

} // namespace logtail
