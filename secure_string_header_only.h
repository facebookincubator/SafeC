// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#else
#include <io.h>
#endif

#define ERR_POTENTIAL_BUFFER_OVERFLOW 34 // matches with ERANGE in errno.h
#define ERR_POTENTIAL_INTEGER_OVERFLOW 75 // matches with EOVERFLOW in errno.h

#ifdef NO_ATTRIBUTE_EXTENSION
#define SECURE_LIB_WARN_UNUSED_RESULT
#define FORMAT_PRINTF
#define NO_RETURN
#elif defined(_WIN32) || defined(_WIN64)
#define SECURE_LIB_WARN_UNUSED_RESULT
#define FORMAT_PRINTF
#define NO_RETURN
#else
#define SECURE_LIB_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define FORMAT_PRINTF __attribute__((__format__(__printf__, 4, 0)))
#define NO_RETURN __attribute__((noreturn))
#endif

#ifndef BAD_PTR
#ifdef __cplusplus
#define BAD_PTR nullptr
#else
#define BAD_PTR NULL
#endif
#endif

static inline void error_print(const char* msg) {
  const size_t msg_length = strlen(msg);
#if !defined(_WIN32) && !defined(_WIN64)
  const ssize_t ret = write(STDERR_FILENO, msg, msg_length);
  (void)ret;
#else
  const int fd = _fileno(stderr);
  if (fd >= 0) {
    _write(fd, msg, (unsigned int)(msg_length));
  }
#endif
}

static inline NO_RETURN void error_with_prefix_msg(
    const char* api_name,
    const char* err_msg_prefix) {
  error_print(err_msg_prefix);
  error_print(api_name);
  error_print("\n");
  abort();
}

static inline NO_RETURN void buffer_overflow_error_with_size(
    const char* api_name,
    size_t destination_size,
    size_t writing_size) {
  char error_msg[128]; // fixture + digits: 87 + 20 + 20 ~= 128
  snprintf(
      error_msg,
      128,
      "[err] Aborting due to potential buffer overflow, writing size %zu to destination %zu in: ",
      writing_size,
      destination_size);
  error_with_prefix_msg(api_name, error_msg);
}

static inline NO_RETURN void buffer_overflow_error(const char* api_name) {
  error_with_prefix_msg(
      api_name, "[err] Aborting due to potential buffer overflow in: ");
}

static inline NO_RETURN void buffer_oob_read_error(const char* api_name) {
  error_with_prefix_msg(
      api_name,
      "[err] Aborting due to potential buffer out-of-bounds read in: ");
}

static inline NO_RETURN void integer_overflow_error(const char* api_name) {
  error_with_prefix_msg(
      api_name, "[err] Aborting due to potential integer overflow in: ");
}

static inline NO_RETURN void null_pointer_error(const char* api_name) {
  error_with_prefix_msg(
      api_name, "[err] Aborting due to unexpected null pointer in: ");
}

/**
 * Bounds checking (i.e. destination) wrapper for std::memcpy. This version
 * aborts the process if there's a possibility of buffer overflow.
 *
 * @param destination
 *      Pointer to the destination where the content is to be copied.
 * @param destination_size
 *      Max number of bytes to modify in the destination (typically the size of
 * the destination buffer).
 * @param source
 *      Pointer to the source of data to be copied.
 * @param count
 *      Number of bytes to copy.
 * @return void *
 *      Pointer to the destination.
 */

static inline void* checked_memcpy(
    void* destination,
    size_t destination_size,
    const void* source,
    size_t count) {
  if (destination_size < count) {
    buffer_overflow_error_with_size(__func__, destination_size, count);
  }
  if (source == BAD_PTR || destination == BAD_PTR) {
    null_pointer_error(__func__);
  }
  return memcpy(destination, source, count);
}

/**
 * Bounds checking (i.e. destination) wrapper for std::memcpy. This version
 * aborts the process if there would be a buffer overflow, and allows for
 * safely writing to an offset within the buffer
 *
 * @param destination
 *      Pointer to the destination where the content is to be copied.
 * @param destination_size
 *      Max number of bytes to modify in the destination (typically the size of
 * the destination buffer).
 * @param offset
 *      The number of bytes to offset the copied bytes into the destination
 * buffer.
 * @param source
 *      Pointer to the source of data to be copied.
 * @param count
 *      Number of bytes to copy.
 * @return void *
 *      Pointer to the destination.
 *      Note - not the offset that was written to.
 *      TODO - may need to reconsider returning the offset as we put this into
 * code
 */

static inline void* checked_memcpy_offset(
    void* destination,
    size_t destination_size,
    size_t offset,
    const void* source,
    size_t count) {
  if (destination_size < count || offset >= destination_size) {
    buffer_overflow_error_with_size(__func__, destination_size - offset, count);
  }

  memcpy((char*)destination + offset, source, count);
  return destination;
}

/**
 * Bounds checking (i.e. both source and destination) wrapper for std::memcpy.
 * This version aborts the process if there's a possibility of buffer overflow.
 *
 * @param destination
 *      Pointer to the destination where the content is to be copied.
 * @param destination_size
 *      Max number of bytes to modify in the destination (typically the size of
 * the destination buffer).
 * @param source
 *      Pointer to the source of data to be copied.
 * @param source_size
 *      Max number of bytes to copy from the source (typically the size of the
 * source buffer).
 * @param count
 *      Number of bytes to copy.
 * @return void *
 *      Pointer to the destination.
 */
static inline void* checked_memcpy_robust(
    void* destination,
    size_t destination_size,
    const void* source,
    size_t source_size,
    size_t count) {
  if (destination_size < count || source_size < count) {
    buffer_overflow_error(__func__);
  }
  return memcpy(destination, source, count);
}

/**
 * Bounds checking (i.e. destination) wrapper for std::memcpy. This version adds
 * bounds checking capability and returns an error code if there's any potential
 * buffer overflow detected. Error handling is mandatory. Note that using this
 * function without error handling does not guarantee security.
 *
 * @param destination
 *      Pointer to the destination where the content is to be copied.
 * @param destination_size
 *      Max number of bytes to modify in the destination (typically the size of
 * the destination buffer).
 * @param source
 *      Pointer to the source of data to be copied.
 * @param count
 *      Number of bytes to copy.
 * @return int
 *      Returns zero on success and non-zero value on error.
 */
SECURE_LIB_WARN_UNUSED_RESULT static inline int try_checked_memcpy(
    void* destination,
    size_t destination_size,
    const void* source,
    size_t count) {
  if (destination_size < count) {
    return ERR_POTENTIAL_BUFFER_OVERFLOW;
  }
  memcpy(destination, source, count);
  return 0;
}

/**
 * Bounds checking (i.e. both source and destination) wrapper for std::memcpy.
 * This version adds bounds checking capability and returns an error code if
 * there's any potential buffer overflow detected. Error handling is mandatory.
 * Note that using this function without error handling does not guarantee
 * security.
 *
 * @param destination
 *      Pointer to the destination where the content is to be copied.
 * @param destination_size
 *      Max number of bytes to modify in the destination (typically the size of
 * the destination buffer).
 * @param source
 *      Pointer to the source of data to be copied.
 * @param source_size
 *      Max number of bytes to copy from the source (typically the size of the
 * source buffer).
 * @param count
 *      Number of bytes to copy.
 * @return int
 *      Returns zero on success and non-zero value on error.
 */
SECURE_LIB_WARN_UNUSED_RESULT static inline int try_checked_memcpy_robust(
    void* destination,
    size_t destination_size,
    const void* source,
    size_t source_size,
    size_t count) {
  if (destination_size < count || source_size < count) {
    return ERR_POTENTIAL_BUFFER_OVERFLOW;
  }
  memcpy(destination, source, count);
  return 0;
}

/**
 * Bounds checking (i.e. destination) wrapper for std::strcat. This version
 * aborts the process if there's a possibility of buffer overflow.
 *
 * @param destination
 *      Pointer to the destination where the content is to be concatenated.
 * @param destination_size
 *      Max number of bytes to modify in the destination (typically the size of
 * the destination buffer).
 * @param source
 *      Pointer to the source of data to be concatenated into destination.
 * @return char *
 *      Pointer to the destination.
 */

static inline char*
checked_strcat(char* destination, size_t destination_size, const char* source) {
  const size_t dest_str_len = strlen(destination);
  const size_t src_str_len = strlen(source);
  const size_t tot_str_len = dest_str_len + src_str_len;

  if (destination_size == 0) {
    buffer_overflow_error_with_size(__func__, destination_size, tot_str_len);
  }

  if (dest_str_len + src_str_len < dest_str_len) {
    integer_overflow_error(__func__);
  }

  if (destination_size - 1 < tot_str_len) {
    buffer_overflow_error_with_size(
        __func__, destination_size - 1, tot_str_len);
  }
  // We already know lengths, use memcpy
  memcpy(destination + dest_str_len, source, src_str_len);
  *(destination + dest_str_len + src_str_len) = '\0';
  return destination;
}

/**
 * Bounds checking (i.e. destination) wrapper for std::strcat. This version adds
 * bounds checking capability and returns an error code if there's any potential
 * buffer overflow detected. Error handling is mandatory. Note that using this
 * function without error handling does not guarantee security.
 *
 * @param destination
 *      Pointer to the destination where the content is to be concatenated.
 * @param destination_size
 *      Max number of bytes to modify in the destination (typically the size of
 * the destination buffer).
 * @param source
 *      Pointer to the source of data to be concatenated into destination.
 * @return int
 *      Returns zero on success and non-zero value on error.
 */
SECURE_LIB_WARN_UNUSED_RESULT static inline int try_checked_strcat(
    char* destination,
    size_t destination_size,
    const char* source) {
  if (destination_size == 0) {
    return ERR_POTENTIAL_BUFFER_OVERFLOW;
  }

  const size_t dest_str_len = strlen(destination);
  const size_t src_str_len = strlen(source);
  if (dest_str_len + src_str_len < dest_str_len) {
    return ERR_POTENTIAL_INTEGER_OVERFLOW;
  }

  if (destination_size - 1 < dest_str_len + src_str_len) {
    return ERR_POTENTIAL_BUFFER_OVERFLOW;
  }

  memcpy(destination + dest_str_len, source, src_str_len);
  *(destination + dest_str_len + src_str_len) = '\0';
  return 0;
}

/**
 * Bounds checking (i.e. src, dest) wrapper for std::memcmp. This version
 * aborts the process if there's a possibility of reading out-of-bounds.
 *
 * @param ptr1
 *      Pointer to block of memory
 * @param ptr1_size
 *      Max number of bytes that can be read from ptr1 (typically the allocated
 * size of the buffer)
 * @param ptr2
 *      Pointer to block of memory
 * @param ptr2_size
 *      Max number of bytes that can be read from ptr2 (typically the allocated
 * size of the buffer)
 * @param num
 *      Number of bytes to compare
 * @return int
 *      Returns an integral value indicating the relationship between the
 * content of the memory blocks.
 *
 * return value < 0: the first byte that does not match in both memory blocks
 * has a lower value in ptr1 than in ptr2 (if evaluated as unsigned char values)
 *
 * return value == 0: the contents of both memory blocks are equal
 *
 * return value > 0: the first byte that does not match in both memory blocks
 * has a greater value in ptr1 than in ptr2 (if evaluated as unsigned char
 * values)
 */
SECURE_LIB_WARN_UNUSED_RESULT static inline int checked_memcmp(
    const void* ptr1,
    size_t ptr1_size,
    const void* ptr2,
    size_t ptr2_size,
    size_t num) {
  if (num > ptr1_size || num > ptr2_size) {
    buffer_oob_read_error(__func__);
  }

  return memcmp(ptr1, ptr2, num);
}

/**
 * Bounds checking (for both strings) wrapper for std::strncmp.
 * This version aborts the process if there's a possibility of buffer over-read.
 *
 * @param str1
 *      First string to be compared.
 * @param str1_size
 *      Max number of bytes of the first string (typically the size of the first
 * string).
 * @param str2
 *      Second string to be compared.
 * @param str2_size
 *      Max number of bytes of the second string (typically the size of the
 second
 * string).
 * @param count
 *      Number of bytes to compare.
 * @return int
 *      1) < 0: the first character that does not match has a lower value in
 str1 than in str2;
 *      2) 0: the contents of both strings are equal;
 *      3) > 0: the first character that does not match has a greater value in
 str1 than in str2.
 */
static inline int checked_strncmp(
    const char* str1,
    size_t str1_size,
    const char* str2,
    size_t str2_size,
    size_t count) {
  if (str1_size < count || str2_size < count) {
    buffer_oob_read_error(__func__);
  }

  return strncmp(str1, str2, count);
}

/**
 * Bounds checking wrapper for std::memset. This version aborts the process if
 * there's a possibility of writing out-of-bounds.
 *
 * @param destination
 *      Pointer to the destination where the content is to be stored.
 * @param destination_size
 *      Max number of bytes to modify in the destination (typically the size of
 * the destination buffer).
 * @param ch
 *      Byte to fill into the destination.
 * @param count
 *      Number of bytes to store.
 * @return void *
 *      Pointer to the destination.
 */
static inline void* checked_memset(
    void* destination,
    size_t destination_size,
    int ch,
    size_t count) {
  if (count > destination_size) {
    buffer_overflow_error(__func__);
  }

  return memset(destination, ch, count);
}

#undef SECURE_LIB_WARN_UNUSED_RESULT
#undef FORMAT_PRINTF

#ifdef __cplusplus
}
#endif
