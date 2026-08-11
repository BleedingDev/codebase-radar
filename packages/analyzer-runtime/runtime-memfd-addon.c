#define _GNU_SOURCE
#include <node_api.h>

#include <fcntl.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 0x0020
#endif

static napi_value throw_error(napi_env env, const char *code, const char *message) {
  napi_throw_error(env, code, message);
  return NULL;
}

static int read_fd(napi_env env, napi_callback_info info, int *fd) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1) {
    throw_error(env, "ERR_RUNTIME_MEMFD_ARGUMENT", "A file descriptor is required.");
    return 0;
  }
  int32_t value;
  if (napi_get_value_int32(env, args[0], &value) != napi_ok || value < 0) {
    throw_error(env, "ERR_RUNTIME_MEMFD_ARGUMENT", "A non-negative file descriptor is required.");
    return 0;
  }
  *fd = value;
  return 1;
}

static napi_value create_memfd_with_flags(napi_env env, unsigned int flags) {
  int fd = (int)syscall(
    SYS_memfd_create,
    "codebase-radar-runtime",
    MFD_CLOEXEC | MFD_ALLOW_SEALING | flags
  );
  if (fd < 0) {
    return throw_error(env, "ERR_RUNTIME_MEMFD_CREATE", "memfd_create failed.");
  }
  napi_value result;
  if (napi_create_int32(env, fd, &result) != napi_ok) {
    close(fd);
    return throw_error(env, "ERR_RUNTIME_MEMFD_CREATE", "Could not return the memfd descriptor.");
  }
  return result;
}

static napi_value create_data_memfd(napi_env env, napi_callback_info info) {
  (void)info;
  return create_memfd_with_flags(env, MFD_NOEXEC_SEAL);
}

static napi_value create_executable_memfd(napi_env env, napi_callback_info info) {
  (void)info;
  return create_memfd_with_flags(env, MFD_EXEC);
}

static napi_value seal_memfd(napi_env env, napi_callback_info info) {
  int fd;
  if (!read_fd(env, info, &fd)) return NULL;
  const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL | F_SEAL_EXEC;
  if (fcntl(fd, F_ADD_SEALS, required) < 0) {
    return throw_error(env, "ERR_RUNTIME_MEMFD_SEAL", "F_ADD_SEALS failed.");
  }
  const int actual = fcntl(fd, F_GET_SEALS);
  if (actual < 0 || (actual & required) != required) {
    return throw_error(env, "ERR_RUNTIME_MEMFD_SEAL", "F_GET_SEALS did not prove the required seals.");
  }
  napi_value result;
  if (napi_create_uint32(env, (uint32_t)actual, &result) != napi_ok) {
    return throw_error(env, "ERR_RUNTIME_MEMFD_SEAL", "Could not return the memfd seals.");
  }
  return result;
}

static napi_value get_memfd_seals(napi_env env, napi_callback_info info) {
  int fd;
  if (!read_fd(env, info, &fd)) return NULL;
  const int actual = fcntl(fd, F_GET_SEALS);
  if (actual < 0) {
    return throw_error(env, "ERR_RUNTIME_MEMFD_SEAL", "F_GET_SEALS failed.");
  }
  napi_value result;
  if (napi_create_uint32(env, (uint32_t)actual, &result) != napi_ok) {
    return throw_error(env, "ERR_RUNTIME_MEMFD_SEAL", "Could not return the memfd seals.");
  }
  return result;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor descriptors[] = {
    { "createData", NULL, create_data_memfd, NULL, NULL, NULL, napi_default, NULL },
    { "createExecutable", NULL, create_executable_memfd, NULL, NULL, NULL, napi_default, NULL },
    { "seal", NULL, seal_memfd, NULL, NULL, NULL, napi_default, NULL },
    { "getSeals", NULL, get_memfd_seals, NULL, NULL, NULL, napi_default, NULL },
  };
  if (napi_define_properties(env, exports, 4, descriptors) != napi_ok) {
    napi_throw_error(env, "ERR_RUNTIME_MEMFD_INIT", "Could not initialize the memfd bridge.");
    return NULL;
  }
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
