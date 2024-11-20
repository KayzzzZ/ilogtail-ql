// Copyright 2022 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific l

#include "K8sMetadata.h"

#include <chrono>
#include <ctime>
#include <thread>

#include "common/MachineInfoUtil.h"
#include "common/http/Curl.h"
#include "common/http/HttpRequest.h"
#include "common/http/HttpResponse.h"
#include "logger/Logger.h"

using namespace std;

namespace logtail {

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

K8sMetadata::K8sMetadata(size_t cacheSize, int32_t fetchIntervalSec)
        : containerCache(cacheSize, 0), 
        ipCache(cacheSize, 0), 
        mFetchIntervalSeconds(fetchIntervalSec) {
    mServiceHost = STRING_FLAG(loong_collector_singleton_service);
    mServicePort = INT32_FLAG(loong_collector_singleton_port);
    mFlag = true;
    mPeriodicalRunner = std::thread(&K8sMetadata::LocalHostMetaRefresher, this);
}

bool K8sMetadata::FromInfoJson(const Json::Value& json, k8sContainerInfo& info) {
    if (!json.isMember(imageKey) || !json.isMember(labelsKey) || !json.isMember(namespaceKey)
        || !json.isMember(workloadKindKey) || !json.isMember(workloadNameKey)) {
        return false;
    }

    for (const auto& key : json[imageKey].getMemberNames()) {
        if (json[imageKey].isMember(key)) {
            info.images[key] = json[imageKey][key].asString();
        }
    }
    for (const auto& key : json[labelsKey].getMemberNames()) {
        if (json[labelsKey].isMember(key)) {
            info.labels[key] = json[labelsKey][key].asString();

            if (key == appIdKey) {
                info.appId = json[labelsKey][key].asString();
            }
        }
    }

    info.k8sNamespace = json[namespaceKey].asString();
    if (json.isMember(serviceNameKey)) {
        info.serviceName = json[serviceNameKey].asString();
    }
    info.workloadKind = json[workloadKindKey].asString();
    info.workloadName = json[workloadNameKey].asString();
    info.timestamp = std::time(0);
    return true;
}

bool ContainerInfoIsExpired(std::shared_ptr<k8sContainerInfo> info) {
    if (info == nullptr) {
        return false;
    }
    std::time_t now = std::time(0);
    std::chrono::system_clock::time_point th1 = std::chrono::system_clock::from_time_t(info->timestamp);
    std::chrono::system_clock::time_point th2 = std::chrono::system_clock::from_time_t(now);
    std::chrono::duration<double> diff = th2 - th1;
    double seconds_diff = diff.count();
    if (seconds_diff > 600) { // 10 minutes in seconds
        return true;
    }
    return false;
}

bool K8sMetadata::FromContainerJson(const Json::Value& json, std::shared_ptr<ContainerData> data) {
    if (!json.isObject()) {
        return false;
    }
    for (const auto& key : json.getMemberNames()) {
        k8sContainerInfo info;
        bool fromJsonIsOk = FromInfoJson(json[key], info);
        if (!fromJsonIsOk) {
            continue;
        }
        data->containers[key] = info;
    }
    return true;
}

// TODO @qianlu.kk how to remove callbacks...
void K8sMetadata::ResiterHostMetadataCallback(HostMetadataPostHandler&& handler) {
    std::lock_guard lk(mMtx);
    mHostMetaCallback.push_back(std::move(handler));
}

void K8sMetadata::LocalHostMetaRefresher() {
    Json::Value jsonObj;
    jsonObj["keys"].append(mHostIp);
    Json::StreamWriterBuilder writer;
    std::string output = Json::writeString(writer, jsonObj);
    while(mFlag) {
        std::vector<std::string> podIpVec;
        SendRequestToOperator(mServiceHost, output, containerInfoType::HostInfo, podIpVec);
        // do callbacks
        {
            std::lock_guard lk(mMtx);
            for (size_t i = 0 ; i < mHostMetaCallback.size(); i ++ ) {
                
                bool res = mHostMetaCallback[i](podIpVec);
                LOG_DEBUG(sLogger, ("cb status", res) ("cb index", i));
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(mFetchIntervalSeconds));
    }
}

bool K8sMetadata::SendRequestToOperator(const std::string& urlHost,
                                        const std::string& output,
                                        containerInfoType infoType, 
                                        std::vector<std::string>& resKey) {
    std::unique_ptr<HttpRequest> request;
    HttpResponse res;
    std::string path = "/metadata/containerid";
    if (infoType == containerInfoType::IpInfo) {
        path = "/metadata/ip";
    } else if (infoType == containerInfoType::HostInfo) {
        path = "/metadata/host";
    }

    request = std::make_unique<HttpRequest>(
        "GET", false, mServiceHost, mServicePort, path, "", map<std::string, std::string>(), output, 30, 3);
    bool success = SendHttpRequest(std::move(request), res);
    if (success) {
        if (res.GetStatusCode() != 200) {
            LOG_DEBUG(sLogger, ("fetch k8s meta from one operator fail, code is ", res.GetStatusCode()));
            return false;
        }
        Json::CharReaderBuilder readerBuilder;
        std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
        Json::Value root;
        std::string errors;

        auto& responseBody = *res.GetBody<std::string>();
        if (reader->parse(responseBody.c_str(), responseBody.c_str() + responseBody.size(), &root, &errors)) {
            std::shared_ptr<ContainerData> data = std::make_shared<ContainerData>();
            if (data == nullptr) {
                return false;
            }
            if (!FromContainerJson(root, data)) {
                LOG_DEBUG(sLogger, ("from container json error:", "SetIpCache"));
            } else {
                for (const auto& pair : data->containers) {
                    // record result
                    resKey.push_back(pair.first);
                    // update cache
                    if (infoType == containerInfoType::ContainerIdInfo) {
                        containerCache.insert(pair.first, std::make_shared<k8sContainerInfo>(pair.second));
                    } else {
                        ipCache.insert(pair.first, std::make_shared<k8sContainerInfo>(pair.second));
                    }
                }
            }

            if (infoType == containerInfoType::ContainerIdInfo) {
                SetContainerCache(root);
            } else {
                SetIpCache(root);
            }
        } else {
            LOG_DEBUG(sLogger, ("JSON parse error:", errors));
            return false;
        }

        return true;
    } else {
        LOG_DEBUG(sLogger, ("fetch k8s meta from one operator fail", urlHost));
        return false;
    }
}

std::vector<std::string> K8sMetadata::GetByContainerIdsFromServer(std::vector<std::string> containerIds) {
    Json::Value jsonObj;
    for (auto& str : containerIds) {
        jsonObj["keys"].append(str);
    }
    std::vector<std::string> res;
    Json::StreamWriterBuilder writer;
    std::string output = Json::writeString(writer, jsonObj);
    SendRequestToOperator(mServiceHost, output, containerInfoType::ContainerIdInfo, res);
    return res;
}

void K8sMetadata::GetByLocalHostFromServer() {
    Json::Value jsonObj;
    jsonObj["keys"].append(mHostIp);
    Json::StreamWriterBuilder writer;
    std::string output = Json::writeString(writer, jsonObj);
    std::vector<std::string> podIpVec;
    SendRequestToOperator(mServiceHost, output, containerInfoType::HostInfo, podIpVec);
}

void K8sMetadata::SetContainerCache(const Json::Value& root) {
    std::shared_ptr<ContainerData> data = std::make_shared<ContainerData>();
    if (data == nullptr) {
        return;
    }
    if (!FromContainerJson(root, data)) {
        LOG_DEBUG(sLogger, ("from container json error:", "SetContainerCache"));
    } else {
        for (const auto& pair : data->containers) {
            containerCache.insert(pair.first, std::make_shared<k8sContainerInfo>(pair.second));
        }
    }
}

void K8sMetadata::SetIpCache(const Json::Value& root) {
    std::shared_ptr<ContainerData> data = std::make_shared<ContainerData>();
    if (data == nullptr) {
        return;
    }
    if (!FromContainerJson(root, data)) {
        LOG_DEBUG(sLogger, ("from container json error:", "SetIpCache"));
    } else {
        for (const auto& pair : data->containers) {
            ipCache.insert(pair.first, std::make_shared<k8sContainerInfo>(pair.second));
        }
    }
}

std::vector<std::string> K8sMetadata::GetByIpsFromServer(std::vector<std::string> ips) {
    Json::Value jsonObj;
    for (auto& str : ips) {
        jsonObj["keys"].append(str);
    }
    std::vector<std::string> res;
    Json::StreamWriterBuilder writer;
    std::string output = Json::writeString(writer, jsonObj);
    SendRequestToOperator(mServiceHost, output, containerInfoType::IpInfo, res);
    return res;
}

std::shared_ptr<k8sContainerInfo> K8sMetadata::GetInfoByContainerIdFromCache(const std::string& containerId) {
    if (containerId.empty()) {
        return nullptr;
    }
    return containerCache.get(containerId);
}

std::shared_ptr<k8sContainerInfo> K8sMetadata::GetInfoByIpFromCache(const std::string& ip) {
    if (ip.empty()) {
        return nullptr;
    }
    std::shared_ptr<k8sContainerInfo> ip_info = ipCache.get(ip);
    if (ip_info == nullptr) {
        return nullptr;
    }
    if (ContainerInfoIsExpired(ip_info)) {
        return nullptr;
    }
    return ip_info;
}

} // namespace logtail
