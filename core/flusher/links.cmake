
# Copyright 2024 iLogtail Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# This file is used to link external source files in flusher directory

<<<<<<< HEAD:core/flusher/links.cmake
macro(flusher_link target_name)
    # link external libraries
endmacro()
=======
cmake_minimum_required(VERSION 3.22)
project(pipeline)

file(GLOB LIB_SOURCE_FILES *.cpp *.h)
append_source_files(LIB_SOURCE_FILES)
add_library(${PROJECT_NAME} STATIC ${LIB_SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} models)
target_link_libraries(${PROJECT_NAME} plugin)
target_link_libraries(${PROJECT_NAME} plugin_instance)
target_link_libraries(${PROJECT_NAME} ebpf)

>>>>>>> f7ffe4f5 (add ebpf input (#1557)):core/pipeline/CMakeLists.txt
