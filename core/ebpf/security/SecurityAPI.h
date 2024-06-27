//
// Created by qianlu on 2024/6/19.
//

#ifndef LOGTAIL_SYSAK_EXPORT_H
#define LOGTAIL_SYSAK_EXPORT_H

#include <vector>
#include <string>
#include <memory>
#include <functional>


enum class SecureEventType {
  TYPE_SOCKET_SECURE,
  TYPE_FILE_SECURE,
  TYPE_PROCESS_SECURE,
  MAX,
};

class AbstractSecurityEvent {
public:
  AbstractSecurityEvent(std::vector<std::pair<std::string, std::string>>&& tags,SecureEventType type, uint64_t ts)
    : tags_(tags), type_(type), timestamp_(ts) {}
  SecureEventType GetEventType() {return type_;}
  std::vector<std::pair<std::string, std::string>> GetAllTags() { return tags_; }
  uint64_t GetTimestamp() { return timestamp_; }

private:
  std::vector<std::pair<std::string, std::string>> tags_;
  SecureEventType type_;
  uint64_t timestamp_;
};

//class ProcessSecurityEvent : public AbstractSecurityEvent {
//public:
//  ProcessSecurityEvent() {}
//private:
//
//};

typedef std::function<void(std::unique_ptr<AbstractSecurityEvent> event)> HandleDataEventFn;
//typedef void (*HandleDataEventFn)(void* ctx, std::unique_ptr<AbstractSecurityEvent> event);

// Config
struct SecureConfig {
public:
  bool enable_libbpf_debug_ = false;
  // common config
  std::string host_name_;
  std::string host_ip_;
  std::string host_path_prefix_;

  // process dynamic config
  std::vector<int> enable_pid_ns_;
  std::vector<int> disable_pid_ns_;

  HandleDataEventFn cb_;

  // network dynamic config
  std::vector<std::string> enable_sips_;
  std::vector<std::string> disable_sips_;
  std::vector<std::string> enable_dips_;
  std::vector<std::string> disable_dips_;
  std::vector<int> enable_sports_;
  std::vector<int> enable_dports_;
  std::vector<int> disable_sports_;
  std::vector<int> disable_dports_;
};


// Network Event
struct NetworkEventInternal {

};

// Process Event
struct ProcessExecvetInternal {

};


// Methods
int handle_network_event(void* ctx, void* data);
int handle_process_event(void* ctx, void* data);


#endif //LOGTAIL_SYSAK_EXPORT_H
