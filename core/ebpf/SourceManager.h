#pragma once

#include <dlfcn.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstring>

namespace logtail {
namespace ebpf {


const int NAME_SIZE = 64;
const int INDEX_SIZE = 64;
const int TABLE_SIZE = 64;

struct unity_index {
    char name[NAME_SIZE];
    char index[INDEX_SIZE];
};

struct unity_value {
    char name[NAME_SIZE];
    double value;
};

struct unity_log {
    char name[NAME_SIZE];
    char* log;
};

struct unity_line {
    char table[TABLE_SIZE];
    struct unity_index indexs[4];
    struct unity_value values[32];
    struct unity_log logs[1];
};

struct unity_lines {
    int num;
    struct unity_line *line;
};

typedef struct init_param {
  std::string btf;
  int32_t btf_size;
  std::string so;
  int32_t so_size;
  long uprobe_offset;
  long upca_offset;
  long upps_offset;
  long upcr_offset;
} init_param_t;

using init_func = int (*)(void *);
using call_func = int (*)(int, struct unity_lines *);
using deinit_func = void (*)();


class source_manager {
public:
    source_manager() : handle(nullptr), initPluginFunc(nullptr), callFunc(nullptr), deinitPluginFunc(nullptr) {}

    ~source_manager() {
        clearPlugin();
    }

    bool initPlugin(const std::string& libPath, const std::string& soPath) {
      // load libsockettrace.so
      handle = dlopen(libPath.c_str(), RTLD_NOW);
      if (!handle) {
        std::cerr << "[SourceManager] dlopen error: " << dlerror() << std::endl;
        return false;
      }
      std::cout << "[SourceManager] successfully open " << libPath << std::endl;

      initPluginFunc = (init_func)dlsym(handle, "init");
      callFunc = (call_func)dlsym(handle, "call");
      deinitPluginFunc = (deinit_func)dlsym(handle, "deinit");

      if (!initPluginFunc || !callFunc || !deinitPluginFunc) {
        std::cerr << "dlsym error: " << dlerror() << std::endl;
        dlclose(handle);
        return false;
      } else {
        std::cout << "[SourceManager] succesfully get init/call/deinit func address for " << libPath << std::endl;
      }

      void* init_param = nullptr;
      if (std::string::npos != libPath.find("sockettrace.so")) {
        // load function and address

        // fill init_param
        init_param_t* config = new init_param_t;
        // TODO @qianlu.kk make it configurable .. 
        config->so = "/usr/local/ilogtail/libsockettrace.so";
        config->so_size = config->so.length();
        Dl_info dlinfo;
        int err;
        void* cleanup_dog_ptr = dlsym(handle, "ebpf_cleanup_dog");
        if (nullptr == cleanup_dog_ptr) {
          std::cout << "[SourceManager] get ebpf_cleanup_dog address failed!" << std::endl;
        } else {
          std::cout << "[SourceManager] successfully get ebpf_cleanup_dog address" << std::endl;
        }
        err = dladdr(cleanup_dog_ptr, &dlinfo);
        if (!err)
        {
          printf("[SourceManager] ebpf_cleanup_dog laddr failed, err:%s\n", strerror(err));
        } else {
          config->uprobe_offset = (long)dlinfo.dli_saddr - (long)dlinfo.dli_fbase;
          std::cout << "[SourceManager] successfully get ebpf_cleanup_dog dlinfo, uprobe_offset:" << config->uprobe_offset << std::endl;
        }

        void* ebpf_update_conn_addr_ptr = dlsym(handle, "ebpf_update_conn_addr");
        if (nullptr == ebpf_update_conn_addr_ptr) {
          std::cout << "[SourceManager] get ebpf_update_conn_addr address failed!" << std::endl;
        } else {
          std::cout << "[SourceManager] successfully get ebpf_update_conn_addr address" << std::endl;
        }
        err = dladdr(ebpf_update_conn_addr_ptr, &dlinfo);
        if (!err)
        {
          printf("[SourceManager] ebpf_update_conn_addr laddr failed, err:%s\n", strerror(err));
        } else {
          config->upca_offset = (long)dlinfo.dli_saddr - (long)dlinfo.dli_fbase;
          std::cout << "[SourceManager] successfully get ebpf_update_conn_addr dlinfo, upca_offset" << config->upca_offset << std::endl;
        }

        void* ebpf_disable_process_ptr = dlsym(handle, "ebpf_disable_process");
        if (nullptr == ebpf_disable_process_ptr) {
          std::cout << "[SourceManager] get ebpf_disable_process address failed!" << std::endl;
        } else {
          std::cout << "[SourceManager] successfully get ebpf_disable_process address" << std::endl;
        }
        err = dladdr(ebpf_disable_process_ptr, &dlinfo);
        if (!err)
        {
          printf("[SourceManager] ebpf_disable_process laddr failed, err:%s\n", strerror(err));
        } else {
          config->upps_offset = (long)dlinfo.dli_saddr - (long)dlinfo.dli_fbase;
          std::cout << "[SourceManager] successfully get ebpf_disable_process dlinfo, upps_offset:" << config->upps_offset << std::endl;
        }

        void* ebpf_update_conn_role_ptr = dlsym(handle, "ebpf_update_conn_role");
        if (nullptr == ebpf_update_conn_role_ptr) {
          std::cout << "[SourceManager] get ebpf_update_conn_role address failed!" << std::endl;
        } else {
          std::cout << "[SourceManager] successfully get ebpf_update_conn_role address" << std::endl;
        }
        err = dladdr(ebpf_update_conn_role_ptr, &dlinfo);
        if (!err)
        {
          printf("[SourceManager] ebpf_update_conn_role laddr failed, err:%s\n", strerror(err));
        } else {
          config->upcr_offset = (long)dlinfo.dli_saddr - (long)dlinfo.dli_fbase;
          std::cout << "[SourceManager] successfully get ebpf_update_conn_role dlinfo, upcr_offset:" << config->upcr_offset << std::endl;
        }
        init_param = (void*)config;
      }

      initPluginFunc(init_param);
      return true;
    }

    void runCore() {

        std::cout << "begin to run core" << std::endl;
        while (true) {
            std::cout << "before call" << std::endl;
            std::cout << "after call" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(10));
      }
    }
    void clearPlugin() {
        if (handle) {
            if (deinitPluginFunc)
                deinitPluginFunc();
            dlclose(handle);
        }
    }
private:
    void *handle;
    init_func initPluginFunc;
    call_func callFunc;
    deinit_func deinitPluginFunc;
};

}
}