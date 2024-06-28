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

#pragma once

#include <dlfcn.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <cstring>
#include <atomic>

#include "ebpf/include/ProcessApi.h"
#include "ebpf/include/SysAkApi.h"
#include "ebpf/include/SockettraceApi.h"
#include "common/DynamicLibHelper.h"

namespace logtail {
namespace ebpf {

enum class eBPFPluginType {
  SOCKETTRACE = 0,
  PROCESS = 1,
  MAX = 2,
};

class SourceManager {
public:
    SourceManager(const SourceManager&) = delete;
    SourceManager& operator=(const SourceManager&) = delete;

    static SourceManager* GetInstance() {
        static SourceManager instance;
        return &instance;
    }

    bool DynamicLibLoadSucess(eBPFPluginType type);

    bool LoadAndStartDynamicLib(eBPFPluginType type, void* config);
    bool ReleaseDynamicLib(eBPFPluginType type);
    void UpdateConfig(eBPFPluginType type, void* config);

    bool LoadSockettraceProbe();
    bool StartSockettraceProbe(SockettraceConfig* config);
    bool UpdateSockettraceProbeConfig(SockettraceConfig* config);
    bool StopSockettraceProbe();

    bool LoadProcessProbe();
    bool StartProcessProbe(SecureConfig* config);
    bool UpdateProcessProbeConfig(SecureConfig* config);
    bool StopProcessProbe();

private:
    SourceManager();
    ~SourceManager();
    enum socket_trace_func {
        INIT = 0,
        UPDATE = 1,
        DEINIT = 2,
        CLEAN_UP_DOG = 3,
        UPDATE_CONN_ADDR = 4,
        DISABLE_PROCESS = 5,
        UPDATE_CONN_ROLE = 6,
        MAX = 7,
    };
    enum process_probe_func {
        INIT = 0,
        UPDATE = 1,
        DEINIT = 2,
        MAX = 3,
    };
    std::vector<std::shared_ptr<DynamicLibLoader>> m_libs_;
    std::map<int, std::vector<void*>> lib_funcs_;
    std::vector<std::atomic_bool> running_;
};

}
}