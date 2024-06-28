

#include <string>

struct SockettraceConfig {
  std::string btf;
  int32_t btf_size;
  std::string so;
  int32_t so_size;
  long uprobe_offset;
  long upca_offset;
  long upps_offset;
  long upcr_offset;
};