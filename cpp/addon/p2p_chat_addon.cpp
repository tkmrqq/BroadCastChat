#include <node.h>
#include <v8.h>
#include "../core/p2p_chat.h"

using namespace v8;

P2PChat chat;
Persistent<Function> js_message_callback;
Persistent<Function> js_participant_callback;

void Start(const FunctionCallbackInfo<Value>& args) {
    chat.initialize();
    chat.start();
}

void SendMessage(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    String::Utf8Value message(isolate, args[0]);
    chat.send_message(std::string(*message));
}

// ... другие функции ...

void Init(Local<Object> exports) {
    NODE_SET_METHOD(exports, "start", Start);
    NODE_SET_METHOD(exports, "sendMessage", SendMessage);
    // ... другие методы ...
}

NODE_MODULE(p2p_chat_addon, Init)