#include <node.h>
#include <node_buffer.h>
#include <node_object_wrap.h>
#include <uv.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
# include <io.h>
# include <fcntl.h>
# include <wchar.h>
# include <windows.h>
# include <share.h>
# include <sys/stat.h>
#endif

#include "magic.h"

using namespace node;
using namespace v8;

class DetectRequest {
public:
  DetectRequest(Local<Function> callback_, const char* magic_source_,
                size_t source_len_, bool source_is_path_, int flags_)
    : magic_source(magic_source_),
      source_len(source_len_),
      source_is_path(source_is_path_),
      flags(flags_) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    callback.Reset(isolate, callback_);

    request.data = this;
    free_error = true;
    error_message = nullptr;
    result = nullptr;

    // Initialize async handle for main thread callback
    uv_async_init(uv_default_loop(), &async_handle, AsyncCallback);
    async_handle.data = this;
  }

  ~DetectRequest() {
    callback.Reset();
    data_buffer.Reset();
    if (data_is_path)
      free(data);
    if (free_error)
      free(error_message);
    free((void*)result);
  }

  static void AsyncCallback(uv_async_t* handle) {
    DetectRequest* detect_req = static_cast<DetectRequest*>(handle->data);

    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    if (!isolate) {
      uv_close((uv_handle_t*)&detect_req->async_handle, CloseCallback);
      return;
    }

    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = isolate->GetCurrentContext();

    Local<Function> callback = Local<Function>::New(isolate, detect_req->callback);

    if (detect_req->error_message) {
      Local<Value> err = v8::Exception::Error(
        v8::String::NewFromUtf8(isolate, detect_req->error_message).ToLocalChecked()
      );
      Local<Value> argv[1] = { err };

      v8::TryCatch try_catch(isolate);
      auto result = callback->Call(context, context->Global(), 1, argv);
      if (try_catch.HasCaught()) {
        // Handle error if needed, but don't throw
      }
    } else {
      Local<Value> argv[2];
      int multi_result_flags =
        (detect_req->flags & (MAGIC_CONTINUE | MAGIC_RAW));

      argv[0] = v8::Null(isolate);

      if (multi_result_flags == (MAGIC_CONTINUE | MAGIC_RAW)) {
        Local<Array> results = v8::Array::New(isolate);
        if (detect_req->result) {
          uint32_t i = 0;
          const char* result_end =
            detect_req->result + strlen(detect_req->result);
          const char* last_match = detect_req->result;
          const char* cur_match;
          while (true) {
            if (!(cur_match = strstr(last_match, "\n- "))) {
              // Append remainder string
              if (last_match < result_end) {
                Local<String> str = v8::String::NewFromUtf8(isolate, last_match).ToLocalChecked();
                results->Set(context, i, str).FromJust();
              }
              break;
            }

            size_t match_len = (cur_match - last_match);
            char* match = new char[match_len + 1];
            strncpy(match, last_match, match_len);
            match[match_len] = '\0';

            Local<String> str = v8::String::NewFromUtf8(isolate, match).ToLocalChecked();
            results->Set(context, i++, str).FromJust();

            delete[] match;
            last_match = cur_match + 3;
          }
        }
        argv[1] = Local<Value>(results);
      } else if (detect_req->result) {
        argv[1] = v8::String::NewFromUtf8(isolate, detect_req->result).ToLocalChecked();
      } else  {
        argv[1] = v8::String::NewFromUtf8(isolate, "").ToLocalChecked();
      }

      v8::TryCatch try_catch(isolate);
      auto result = callback->Call(context, context->Global(), 2, argv);
      if (try_catch.HasCaught()) {
        // Handle error if needed, but don't throw
      }
    }

    // Close the async handle
    uv_close((uv_handle_t*)&detect_req->async_handle, CloseCallback);
  }

  static void CloseCallback(uv_handle_t* handle) {
    DetectRequest* detect_req = static_cast<DetectRequest*>(handle->data);
    delete detect_req;
  }

  uv_work_t request;
  uv_async_t async_handle;
  v8::Persistent<Function> callback;

  char* data;
  size_t data_len;
  bool data_is_path;
  v8::Persistent<Object> data_buffer;

  // libmagic info
  const char* magic_source;
  size_t source_len;
  bool source_is_path;
  int flags;

  bool free_error;
  char* error_message;

  const char* result;
};

static v8::Persistent<Function> constructor;
static const char* fallbackPath;

class Magic : public ObjectWrap {
public:
    v8::Persistent<Object> mgc_buffer;
    size_t mgc_buffer_len;
    const char* msource;
    int mflags;

    Magic(const char* path, int flags) {
      if (path != nullptr) {
        /* Windows blows up trying to look up the path '(null)' returned by
           magic_getpath() */
        if (strncmp(path, "(null)", 6) == 0)
          path = nullptr;
      }
      msource = (path == nullptr ? strdup(fallbackPath) : path);

      // When returning multiple matches, MAGIC_RAW needs to be set so that we
      // can more easily parse the output into an array for the end user
      if (flags & MAGIC_CONTINUE)
        flags |= MAGIC_RAW;

      mflags = flags;
    }

    Magic(Local<Object> buffer, int flags) {
      v8::Isolate* isolate = v8::Isolate::GetCurrent();
      mgc_buffer.Reset(isolate, buffer);
      mgc_buffer_len = Buffer::Length(buffer);
      msource = Buffer::Data(buffer);

      // When returning multiple matches, MAGIC_RAW needs to be set so that we
      // can more easily parse the output into an array for the end user
      if (flags & MAGIC_CONTINUE)
        flags |= MAGIC_RAW;

      mflags = flags;
    }

    ~Magic() {
      if (!mgc_buffer.IsEmpty())
        mgc_buffer.Reset();
      else if (msource != nullptr)
        free((void*)msource);
      msource = nullptr;
    }

    static void New(const v8::FunctionCallbackInfo<v8::Value>& args) {
      v8::Isolate* isolate = args.GetIsolate();
      v8::HandleScope scope(isolate);
#ifndef _WIN32
      int magic_flags = MAGIC_SYMLINK;
#else
      int magic_flags = MAGIC_NONE;
#endif
      Magic* obj;

      if (!args.IsConstructCall()) {
        isolate->ThrowException(v8::Exception::TypeError(
          v8::String::NewFromUtf8(isolate, "Use `new` to create instances of this object.").ToLocalChecked()));
        return;
      }

      if (args.Length() > 1) {
        if (args[1]->IsInt32()) {
          auto maybe_int = args[1]->Int32Value(isolate->GetCurrentContext());
          if (maybe_int.IsJust()) {
            magic_flags = maybe_int.FromJust();
          }
        } else {
          isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Second argument must be an integer").ToLocalChecked()));
          return;
        }
      }

      if (args.Length() > 0) {
        if (args[0]->IsString()) {
          v8::String::Utf8Value str(isolate, args[0]);
          char* path = strdup(*str);
          obj = new Magic(path, magic_flags);
        } else if (Buffer::HasInstance(args[0])) {
          obj = new Magic(args[0].As<Object>(), magic_flags);
        } else if (args[0]->IsInt32()) {
          auto maybe_int = args[0]->Int32Value(isolate->GetCurrentContext());
          if (maybe_int.IsJust()) {
            magic_flags = maybe_int.FromJust();
          }
          obj = new Magic(nullptr, magic_flags);
        } else if (args[0]->IsBoolean()) {
          auto maybe_bool = args[0]->BooleanValue(isolate);
          if (!maybe_bool) {
            char* path = strdup(magic_getpath(nullptr, 0/*FILE_LOAD*/));
            obj = new Magic(path, magic_flags);
          } else {
            obj = new Magic(nullptr, magic_flags);
          }
        } else {
          isolate->ThrowException(v8::Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "First argument must be a string, Buffer, or integer").ToLocalChecked()));
          return;
        }
      } else {
        obj = new Magic(nullptr, magic_flags);
      }

      obj->Wrap(args.This());
      obj->Ref();

      args.GetReturnValue().Set(args.This());
    }

    static void DetectFile(const v8::FunctionCallbackInfo<v8::Value>& args) {
      v8::Isolate* isolate = args.GetIsolate();
      v8::HandleScope scope(isolate);
      Magic* obj = ObjectWrap::Unwrap<Magic>(args.This());

      if (!args[0]->IsString()) {
        isolate->ThrowException(v8::Exception::TypeError(
          v8::String::NewFromUtf8(isolate, "First argument must be a string").ToLocalChecked()));
        return;
      }
      if (!args[1]->IsFunction()) {
        isolate->ThrowException(v8::Exception::TypeError(
          v8::String::NewFromUtf8(isolate, "Second argument must be a callback function").ToLocalChecked()));
        return;
      }

      Local<Function> callback = Local<Function>::Cast(args[1]);

      v8::String::Utf8Value str(isolate, args[0]);

      DetectRequest* detect_req = new DetectRequest(callback,
                                                    obj->msource,
                                                    obj->mgc_buffer_len,
                                                    obj->mgc_buffer.IsEmpty(),
                                                    obj->mflags);
      detect_req->data = strdup(*str);
      detect_req->data_is_path = true;

      int status = uv_queue_work(uv_default_loop(),
                                 &detect_req->request,
                                 Magic::DetectWork,
                                 (uv_after_work_cb)Magic::DetectAfter);
      assert(status == 0);

      args.GetReturnValue().Set(v8::Undefined(isolate));
    }

    static void Detect(const v8::FunctionCallbackInfo<v8::Value>& args) {
      v8::Isolate* isolate = args.GetIsolate();
      v8::HandleScope scope(isolate);
      Magic* obj = ObjectWrap::Unwrap<Magic>(args.This());

      if (args.Length() < 2) {
        isolate->ThrowException(v8::Exception::TypeError(
          v8::String::NewFromUtf8(isolate, "Expecting 2 arguments").ToLocalChecked()));
        return;
      }
      if (!Buffer::HasInstance(args[0])) {
        isolate->ThrowException(v8::Exception::TypeError(
          v8::String::NewFromUtf8(isolate, "First argument must be a Buffer").ToLocalChecked()));
        return;
      }
      if (!args[1]->IsFunction()) {
        isolate->ThrowException(v8::Exception::TypeError(
          v8::String::NewFromUtf8(isolate, "Second argument must be a callback function").ToLocalChecked()));
        return;
      }

      Local<Function> callback = Local<Function>::Cast(args[1]);
      Local<Object> buffer_obj = args[0].As<Object>();

      DetectRequest* detect_req = new DetectRequest(callback,
                                                    obj->msource,
                                                    obj->mgc_buffer_len,
                                                    obj->mgc_buffer.IsEmpty(),
                                                    obj->mflags);
      detect_req->data = Buffer::Data(buffer_obj);
      detect_req->data_len = Buffer::Length(buffer_obj);
      detect_req->data_buffer.Reset(isolate, buffer_obj);
      detect_req->data_is_path = false;

      int status = uv_queue_work(uv_default_loop(),
                                 &detect_req->request,
                                 Magic::DetectWork,
                                 (uv_after_work_cb)Magic::DetectAfter);
      assert(status == 0);

      args.GetReturnValue().Set(args.This());
    }

    static void DetectWork(uv_work_t* req) {
      DetectRequest* detect_req = static_cast<DetectRequest*>(req->data);
      const char* result;
      struct magic_set* magic = magic_open(detect_req->flags
                                           | MAGIC_NO_CHECK_COMPRESS
                                           | MAGIC_ERROR);

      if (magic == nullptr) {
#if NODE_MODULE_VERSION <= 0x000B
        detect_req->error_message =
          strdup(uv_strerror(uv_last_error(uv_default_loop())));
        detect_req->free_error = true;
#else
// XXX libuv 1.x currently has no public cross-platform function to convert an
//     OS-specific error number to a libuv error number. `-errno` should work
//     for *nix, but just passing GetLastError() on Windows will not work ...
# ifdef _MSC_VER
        detect_req->error_message = strdup(uv_strerror(GetLastError()));
        detect_req->free_error = true;
# else
        detect_req->error_message = strdup(uv_strerror(-errno));
        detect_req->free_error = true;
# endif
#endif
      } else if (detect_req->source_is_path) {
        if (magic_load(magic, detect_req->magic_source) == -1
            && magic_load(magic, fallbackPath) == -1) {
          detect_req->error_message = strdup(magic_error(magic));
          magic_close(magic);
          magic = nullptr;
        }
      } else if (magic_load_buffers(magic,
                                    (void**)&detect_req->magic_source,
                                    &detect_req->source_len,
                                    1) == -1) {
        detect_req->error_message = strdup(magic_error(magic));
        magic_close(magic);
        magic = nullptr;
      }

      if (magic == nullptr)
        return;

      if (detect_req->data_is_path) {
#ifdef _WIN32
        // open the file manually to help cope with potential unicode characters
        // in filename
        const char* ofn = detect_req->data;
        int flags = O_RDONLY | O_BINARY;
        int fd = -1;
        int wLen;
        wLen = MultiByteToWideChar(CP_UTF8, 0, ofn, -1, nullptr, 0);
        if (wLen > 0) {
          wchar_t* wfn = (wchar_t*)malloc(wLen * sizeof(wchar_t));
          if (wfn) {
            int wret = MultiByteToWideChar(CP_UTF8, 0, ofn, -1, wfn, wLen);
            if (wret != 0)
              _wsopen_s(&fd, wfn, flags, _SH_DENYNO, _S_IREAD);
            free(wfn);
            wfn = nullptr;
          }
        }
        if (fd == -1) {
          detect_req->free_error = true;
          char const * msg = "Error while opening file";
          detect_req->error_message = strdup(msg);
          magic_close(magic);
          return;
        }
        result = magic_descriptor(magic, fd);
        _close(fd);
#else
        result = magic_file(magic, detect_req->data);
#endif
      } else {
        result = magic_buffer(magic,
                              (const void*)detect_req->data,
                              detect_req->data_len);
      }

      if (result == nullptr) {
        const char* error = magic_error(magic);
        if (error) {
          detect_req->error_message = strdup(error);
          detect_req->free_error = true;
        }
      } else {
        detect_req->result = strdup(result);
      }

      magic_close(magic);
    }

    static void DetectAfter(uv_work_t* req) {
      DetectRequest* detect_req = static_cast<DetectRequest*>(req->data);

      // Instead of calling the callback directly, trigger the async handle
      // to schedule the callback execution on the main thread
      uv_async_send(&detect_req->async_handle);
    }

    static void SetFallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
      v8::Isolate* isolate = args.GetIsolate();

      if (fallbackPath)
        free((void*)fallbackPath);

      fallbackPath = nullptr;
      if (args.Length() > 0 && args[0]->IsString()) {
        v8::String::Utf8Value str(isolate, args[0]);
        if (str.length() > 0)
          fallbackPath = strdup(*str);
      }

      args.GetReturnValue().Set(args.This());
    }

    static void Initialize(Local<Object> target) {
      v8::Isolate* isolate = v8::Isolate::GetCurrent();
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context = isolate->GetCurrentContext();

      Local<FunctionTemplate> tpl = v8::FunctionTemplate::New(isolate, New);

      tpl->InstanceTemplate()->SetInternalFieldCount(1);
      tpl->SetClassName(v8::String::NewFromUtf8(isolate, "Magic").ToLocalChecked());

      // Set prototype methods
      tpl->PrototypeTemplate()->Set(
        v8::String::NewFromUtf8(isolate, "detectFile").ToLocalChecked(),
        v8::FunctionTemplate::New(isolate, DetectFile)
      );
      tpl->PrototypeTemplate()->Set(
        v8::String::NewFromUtf8(isolate, "detect").ToLocalChecked(),
        v8::FunctionTemplate::New(isolate, Detect)
      );

      Local<Function> function = tpl->GetFunction(context).ToLocalChecked();
      constructor.Reset(isolate, function);

      target->Set(context,
                  v8::String::NewFromUtf8(isolate, "setFallback").ToLocalChecked(),
                  v8::FunctionTemplate::New(isolate, SetFallback)->GetFunction(context).ToLocalChecked()).FromJust();

      target->Set(context,
                  v8::String::NewFromUtf8(isolate, "Magic").ToLocalChecked(),
                  function).FromJust();
    }
};

extern "C" {
  static void init(Local<Object> target, Local<Value> unused, Local<Context> context, void* priv) {
    v8::Isolate* isolate = context->GetIsolate();
    v8::HandleScope scope(isolate);
    Magic::Initialize(target);
  }

  NODE_MODULE_CONTEXT_AWARE(magic, init);
}
