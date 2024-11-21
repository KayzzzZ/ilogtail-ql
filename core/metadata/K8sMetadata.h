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
#pragma once
#include <iostream>
#include <string>
#include <curl/curl.h>
#include <atomic>

#include "common/LRUCache.h"
#include "app_config/AppConfig.h"
#include <json/json.h>
#include "common/Flags.h"

DECLARE_FLAG_STRING(loong_collector_singleton_service);
DECLARE_FLAG_INT32(loong_collector_singleton_port);

namespace logtail {

const static std::string appIdKey = "armsAppId";
const static std::string appNameKey = "armsAppName";
const static std::string imageKey = "images";
const static std::string labelsKey = "labels";
const static std::string namespaceKey = "namespace";
const static std::string workloadKindKey = "workloadKind";
const static std::string workloadNameKey = "workloadName";
const static std::string serviceNameKey = "serviceName";
const static std::string podNameKey = "podName";
const static std::string podIpKey = "podIP";
const static std::string envKey = "envs";
const static std::string containerIdKey = "containerIDs";
const static std::string startTimeKey = "startTime";

struct k8sContainerInfo {
    std::unordered_map<std::string, std::string> images;
    std::unordered_map<std::string, std::string> labels;
    std::string k8sNamespace;
    std::string serviceName;
    std::string workloadKind;
    std::string workloadName;
    // ??? 
    std::time_t timestamp;
    std::string appId;
    std::string appName;
    std::string podIp;
    std::string podName;
    std::string serviceName;
    int64_t startTime;
    std::vector<std::string> containerIds;
};

// 定义顶层的结构体
struct ContainerData {
    std::unordered_map<std::string, k8sContainerInfo> containers;
};

enum class containerInfoType {
    ContainerIdInfo,
    IpInfo,
    HostInfo,
};

using HostMetadataPostHandler = std::function<bool(std::vector<std::string>&)>;

class K8sMetadata {
private:
    lru11::Cache<std::string, std::shared_ptr<k8sContainerInfo>> containerCache;
    lru11::Cache<std::string, std::shared_ptr<k8sContainerInfo>> ipCache;
    std::string mServiceHost;
    int32_t mServicePort;
    std::string mHostIp;

    // mPeriodicalRunner will periodically fetch local host metadata.
    std::thread mPeriodicalRunner;
    std::atomic_bool mFlag;
    int32_t mFetchIntervalSeconds;
    std::mutex mMtx;
    std::vector<HostMetadataPostHandler> mHostMetaCallback;

    K8sMetadata(size_t cacheSize, int32_t fetchIntervalSec = 5);
    K8sMetadata(const K8sMetadata&) = delete;
    K8sMetadata& operator=(const K8sMetadata&) = delete;

    void SetIpCache(const Json::Value& root);
    void SetContainerCache(const Json::Value& root);
    bool FromInfoJson(const Json::Value& json, k8sContainerInfo& info);
    bool FromContainerJson(const Json::Value& json, std::shared_ptr<ContainerData> data);
    void LocalHostMetaRefresher();

public:

    static K8sMetadata& GetInstance() {
        static K8sMetadata instance(500);
        return instance;
    }
    ~K8sMetadata() {
        mFlag = false;
        if (mPeriodicalRunner.joinable()) {
            mPeriodicalRunner.join();
        }
    }

    void ResiterHostMetadataCallback(HostMetadataPostHandler&& callback);
    // 公共方法
    // if cache not have,get from server
    std::vector<std::string> GetByContainerIdsFromServer(std::vector<std::string> containerIds);
    // get pod metadatas for local host 
    void GetByLocalHostFromServer();
    // 
    std::vector<std::string> GetByIpsFromServer(std::vector<std::string> ips);
    // get info by container id from cache
    std::shared_ptr<k8sContainerInfo> GetInfoByContainerIdFromCache(const std::string& containerId);
    // get info by ip from cache
    std::shared_ptr<k8sContainerInfo> GetInfoByIpFromCache(const std::string& ip);
    bool SendRequestToOperator(const std::string& urlHost, const std::string& output, containerInfoType infoType, std::vector<std::string>& resKey);

#ifdef APSARA_UNIT_TEST_MAIN
    friend class k8sMetadataUnittest;
#endif
};  
    
} // namespace logtail
