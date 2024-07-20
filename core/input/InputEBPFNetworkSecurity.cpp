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

#include "input/InputEBPFNetworkSecurity.h"

#include "ebpf/security/SecurityServer.h"


using namespace std;

namespace logtail {

const std::string InputEBPFNetworkSecurity::sName = "input_ebpf_sockettraceprobe_security";

bool InputEBPFNetworkSecurity::Init(const Json::Value& config, uint32_t& pluginIdx, Json::Value& optionalGoPipeline) {
    // config string解析成定义的param
    return mSecurityOptions.Init(SecurityFilterType::NETWORK, config, mContext, sName);
}

bool InputEBPFNetworkSecurity::Start() {
    SecurityServer::GetInstance()->AddSecurityOptions(mContext->GetConfigName(), mIndex, &mSecurityOptions, mContext);
<<<<<<< HEAD
    SecurityServer::GetInstance()->InitBPF(BPFSecurityPipelineType::PIPELINE_NETWORK);
=======
    SecurityServer::GetInstance()->Start();
>>>>>>> f7ffe4f5 (add ebpf input (#1557))
    return true;
}

bool InputEBPFNetworkSecurity::Stop(bool isPipelineRemoving) {
    if (!isPipelineRemoving) {
        // TODO: ?
<<<<<<< HEAD
        SecurityServer::GetInstance()->AddSecurityOptions(mContext->GetConfigName(), mIndex, &mSecurityOptions, mContext);
        return SecurityServer::GetInstance()->UpdateBPFConfig(BPFSecurityPipelineType::PIPELINE_NETWORK);

=======
>>>>>>> f7ffe4f5 (add ebpf input (#1557))
    }
    SecurityServer::GetInstance()->RemoveSecurityOptions(mContext->GetConfigName(), mIndex);
    return true;
}

} // namespace logtail
