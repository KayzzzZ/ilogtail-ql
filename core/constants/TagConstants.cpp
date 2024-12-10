// Copyright 2024 iLogtail Authors
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
// See the License for the specific language governing permissions and
// limitations under the License.

#include "TagConstants.h"

namespace logtail {

////////////////////////// COMMON ////////////////////////
    const std::string DEFAULT_TAG_NAMESPACE = "namespace";
    const std::string DEFAULT_TAG_HOST_NAME = "host_name";
    const std::string DEFAULT_TAG_HOST_IP = "host_ip";
    const std::string DEFAULT_TAG_POD_NAME = "pod_name";
    const std::string DEFAULT_TAG_POD_UID = "pod_uid";
    const std::string DEFAULT_TAG_CONTAINER_NAME = "container_name";
    const std::string DEFAULT_TAG_CONTAINER_IP = "container_ip";
    const std::string DEFAULT_TAG_IMAGE_NAME = "image_name";

////////////////////////// LOG ////////////////////////
#ifndef __ENTERPRISE__ // 开源版
    const std::string DEFAULT_LOG_TAG_HOST_NAME = DEFAULT_TAG_HOST_NAME;
    const std::string DEFAULT_LOG_TAG_NAMESPACE = DEFAULT_TAG_NAMESPACE;
    const std::string DEFAULT_LOG_TAG_POD_NAME = DEFAULT_TAG_POD_NAME;
    const std::string DEFAULT_LOG_TAG_POD_UID = DEFAULT_TAG_POD_UID;
    const std::string DEFAULT_LOG_TAG_CONTAINER_NAME = DEFAULT_TAG_CONTAINER_NAME;
    const std::string DEFAULT_LOG_TAG_CONTAINER_IP = DEFAULT_TAG_CONTAINER_IP;
    const std::string DEFAULT_LOG_TAG_IMAGE_NAME = DEFAULT_TAG_IMAGE_NAME;
    const std::string DEFAULT_LOG_TAG_FILE_OFFSET = "file_offset";
    const std::string DEFAULT_LOG_TAG_FILE_INODE = "file_inode";
    const std::string DEFAULT_LOG_TAG_FILE_PATH = "file_path";

    const std::string DEFAULT_LOG_TAG_HOST_IP = DEFAULT_TAG_HOST_IP;
#else
    const std::string DEFAULT_LOG_TAG_HOST_NAME = "__hostname__";
    const std::string DEFAULT_LOG_TAG_NAMESPACE = "_namespace_";
    const std::string DEFAULT_LOG_TAG_POD_NAME = "_pod_name_";
    const std::string DEFAULT_LOG_TAG_POD_UID = "_pod_uid_";
    const std::string DEFAULT_LOG_TAG_CONTAINER_NAME = "_container_name_";
    const std::string DEFAULT_LOG_TAG_CONTAINER_IP = "_container_ip_";
    const std::string DEFAULT_LOG_TAG_IMAGE_NAME = "_image_name_";
    const std::string DEFAULT_LOG_TAG_FILE_OFFSET = "__file_offset__";
    const std::string DEFAULT_LOG_TAG_FILE_INODE = "__inode__";
    const std::string DEFAULT_LOG_TAG_FILE_PATH = "__path__";
    
    const std::string DEFAULT_LOG_TAG_USER_DEFINED_ID = "__user_defined_id__";
#endif

////////////////////////// METRIC ////////////////////////
    const std::string DEFAULT_METRIC_TAG_NAMESPACE = DEFAULT_TAG_NAMESPACE;
    const std::string DEFAULT_METRIC_TAG_POD_NAME = DEFAULT_TAG_POD_NAME;
    const std::string DEFAULT_METRIC_TAG_POD_UID = DEFAULT_TAG_POD_UID;
    const std::string DEFAULT_METRIC_TAG_CONTAINER_NAME = DEFAULT_TAG_CONTAINER_NAME;
    const std::string DEFAULT_METRIC_TAG_CONTAINER_IP = DEFAULT_TAG_CONTAINER_IP;
    const std::string DEFAULT_METRIC_TAG_IMAGE_NAME = DEFAULT_TAG_IMAGE_NAME;
    const std::string DEFAULT_METRIC_TAG_PEER_POD_NAME = "pod_name";
    const std::string DEFAULT_METRIC_TAG_POD_IP = "pod_ip";
    const std::string DEFAULT_METRIC_TAG_PEER_POD_IP = "peer_pod_ip";
    const std::string DEFAULT_METRIC_TAG_WORKLOAD_KIND = "workload_kind";
    const std::string DEFAULT_METRIC_TAG_PEER_WORKLOAD_KIND = "peer_workload_kind";
    const std::string DEFAULT_METRIC_TAG_WORKLOAD_NAME = "workload_name";
    const std::string DEFAULT_METRIC_TAG_PEER_WORKLOAD_NAME = "peer_workload_name";
    const std::string DEFAULT_METRIC_TAG_SERVICE_NAME = "service_name";
    const std::string DEFAULT_METRIC_TAG_PEER_SERVICE_NAME = "peer_service_name";
    const std::string DEFAULT_METRIC_TAG_HOST_NAME = "host_name";
    const std::string DEFAULT_METRIC_TAG_HOST_IP = "host_ip";
    const std::string DEFAULT_METRIC_TAG_PROCESS_PID = "process_pid";
    const std::string DEFAULT_METRIC_TAG_CONTAINER_ID = "container_id";

    const std::string DEFAULT_METRIC_TAG_ARMS_APP_ID = "arms_app_id";
    const std::string DEFAULT_METRIC_TAG_ARMS_APP_NAME = "arms_app_name";
    const std::string DEFAULT_METRIC_TAG_RPC = "rpc";
    const std::string DEFAULT_METRIC_TAG_RPC_TYPE = "rpc_type";
    const std::string DEFAULT_METRIC_TAG_CALL_KIND = "call_kind";
    const std::string DEFAULT_METRIC_TAG_CALL_TYPE = "call_type";
    const std::string DEFAULT_METRIC_TAG_STATUS_CODE = "status_code";

////////////////////////// TRACE ////////////////////////
    const std::string DEFAULT_TRACE_TAG_TRACE_ID = "traceId";
    const std::string DEFAULT_TRACE_TAG_SPAN_ID = "spanId";
    const std::string DEFAULT_TRACE_TAG_PARENT_ID = "parentSpanId";
    const std::string DEFAULT_TRACE_TAG_SPAN_NAME = "spanName";
    const std::string DEFAULT_TRACE_TAG_SERVICE_NAME = "serviceName";
    const std::string DEFAULT_TRACE_TAG_START_TIME_NANO = "startTime";
    const std::string DEFAULT_TRACE_TAG_END_TIME_NANO = "endTime";
    const std::string DEFAULT_TRACE_TAG_DURATION = "duration";
    const std::string DEFAULT_TRACE_TAG_ATTRIBUTES = "attributes";
    const std::string DEFAULT_TRACE_TAG_RESOURCE = "resources";
    const std::string DEFAULT_TRACE_TAG_LINKS = "links";
    const std::string DEFAULT_TRACE_TAG_EVENTS = "events";
    const std::string DEFAULT_TRACE_TAG_TIMESTAMP = "timestamp";
    const std::string DEFAULT_TRACE_TAG_STATUS_CODE = "statusCode";
    const std::string DEFAULT_TRACE_TAG_STATUS_MESSAGE = "statusMessage";
    const std::string DEFAULT_TRACE_TAG_SPAN_KIND = "kind";
    const std::string DEFAULT_TRACE_TAG_TRACE_STATE = "traceState";
    // for arms
    const std::string DEFAULT_TRACE_TAG_APP_ID = "pid";
    const std::string DEFAULT_TRACE_TAG_IP = "ip";


///////// TOBE MERGED TRACE /////////
    const std::string DEFAULT_TRACE_TAG_K8S_NAMESPACE = "k8s.namespace.name";
    const std::string DEFAULT_TRACE_TAG_K8S_PEER_NAMESPACE = "k8s.peer.namespace.name";
    const std::string DEFAULT_TRACE_TAG_K8S_POD_NAME = "k8s.pod.name";
    const std::string DEFAULT_TRACE_TAG_K8S_PEER_POD_NAME = "k8s.pod.name";
    const std::string DEFAULT_TRACE_TAG_K8S_POD_UID = "k8s.pod.uid";
    const std::string DEFAULT_TRACE_TAG_K8S_POD_IP = "k8s.pod.ip";
    const std::string DEFAULT_TRACE_TAG_K8S_PEER_POD_IP = "k8s.peer.pod.ip";
    const std::string DEFAULT_TRACE_TAG_K8S_WORKLOAD_KIND = "k8s.workload.kind";
    const std::string DEFAULT_TRACE_TAG_K8S_PEER_WORKLOAD_KIND = "k8s.peer.workload.kind";
    const std::string DEFAULT_TRACE_TAG_K8S_WORKLOAD_NAME = "k8s.workload.name";
    const std::string DEFAULT_TRACE_TAG_K8S_PEER_WORKLOAD_NAME = "k8s.peer.workload.name";
    const std::string DEFAULT_TRACE_TAG_K8S_K8S_SERVICE_NAME = "k8s.service.name";
    const std::string DEFAULT_TRACE_TAG_K8S_PEER_SERVICE_NAME = "k8s.peer.service.name";
    const std::string DEFAULT_TRACE_TAG_HOST_NAME = "host.name";
    const std::string DEFAULT_TRACE_TAG_HOST_IP = "host.ip";
    const std::string DEFAULT_TRACE_TAG_PROCESS_PID = "process.pid";
    const std::string DEFAULT_TRACE_TAG_CONTAINER_NAME = "container.name";
    const std::string DEFAULT_TRACE_TAG_CONTAINER_ID = "container.id";
    const std::string DEFAULT_TRACE_TAG_IMAGE_NAME = "container.image.name";
} // namespace logtail