// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: client_peers.proto

#include "client_peers.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
class ClientPeersGetRequestDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<ClientPeersGetRequest> _instance;
} _ClientPeersGetRequest_default_instance_;
class ClientPeersGetResponseDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<ClientPeersGetResponse> _instance;
} _ClientPeersGetResponse_default_instance_;
static void InitDefaultsscc_info_ClientPeersGetRequest_client_5fpeers_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::_ClientPeersGetRequest_default_instance_;
    new (ptr) ::ClientPeersGetRequest();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::ClientPeersGetRequest::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<0> scc_info_ClientPeersGetRequest_client_5fpeers_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, InitDefaultsscc_info_ClientPeersGetRequest_client_5fpeers_2eproto}, {}};

static void InitDefaultsscc_info_ClientPeersGetResponse_client_5fpeers_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::_ClientPeersGetResponse_default_instance_;
    new (ptr) ::ClientPeersGetResponse();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::ClientPeersGetResponse::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<0> scc_info_ClientPeersGetResponse_client_5fpeers_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, InitDefaultsscc_info_ClientPeersGetResponse_client_5fpeers_2eproto}, {}};

static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_client_5fpeers_2eproto[2];
static const ::PROTOBUF_NAMESPACE_ID::EnumDescriptor* file_level_enum_descriptors_client_5fpeers_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_client_5fpeers_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_client_5fpeers_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::ClientPeersGetRequest, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::ClientPeersGetResponse, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::ClientPeersGetResponse, status_),
  PROTOBUF_FIELD_OFFSET(::ClientPeersGetResponse, peers_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::ClientPeersGetRequest)},
  { 5, -1, sizeof(::ClientPeersGetResponse)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::_ClientPeersGetRequest_default_instance_),
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::_ClientPeersGetResponse_default_instance_),
};

const char descriptor_table_protodef_client_5fpeers_2eproto[] =
  "\n\022client_peers.proto\"\027\n\025ClientPeersGetRe"
  "quest\"\206\001\n\026ClientPeersGetResponse\022.\n\006stat"
  "us\030\001 \001(\0162\036.ClientPeersGetResponse.Status"
  "\022\r\n\005peers\030\002 \003(\t\"-\n\006Status\022\020\n\014STATUS_UNSE"
  "T\020\000\022\006\n\002OK\020\001\022\t\n\005ERROR\020\002B&\n\025sawtooth.sdk.p"
  "rotobufP\001Z\013client_peerb\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_client_5fpeers_2eproto_deps[1] = {
};
static ::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase*const descriptor_table_client_5fpeers_2eproto_sccs[2] = {
  &scc_info_ClientPeersGetRequest_client_5fpeers_2eproto.base,
  &scc_info_ClientPeersGetResponse_client_5fpeers_2eproto.base,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_client_5fpeers_2eproto_once;
static bool descriptor_table_client_5fpeers_2eproto_initialized = false;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_client_5fpeers_2eproto = {
  &descriptor_table_client_5fpeers_2eproto_initialized, descriptor_table_protodef_client_5fpeers_2eproto, "client_peers.proto", 230,
  &descriptor_table_client_5fpeers_2eproto_once, descriptor_table_client_5fpeers_2eproto_sccs, descriptor_table_client_5fpeers_2eproto_deps, 2, 0,
  schemas, file_default_instances, TableStruct_client_5fpeers_2eproto::offsets,
  file_level_metadata_client_5fpeers_2eproto, 2, file_level_enum_descriptors_client_5fpeers_2eproto, file_level_service_descriptors_client_5fpeers_2eproto,
};

// Force running AddDescriptors() at dynamic initialization time.
static bool dynamic_init_dummy_client_5fpeers_2eproto = (  ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptors(&descriptor_table_client_5fpeers_2eproto), true);
const ::PROTOBUF_NAMESPACE_ID::EnumDescriptor* ClientPeersGetResponse_Status_descriptor() {
  ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&descriptor_table_client_5fpeers_2eproto);
  return file_level_enum_descriptors_client_5fpeers_2eproto[0];
}
bool ClientPeersGetResponse_Status_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
    case 2:
      return true;
    default:
      return false;
  }
}

#if (__cplusplus < 201703) && (!defined(_MSC_VER) || _MSC_VER >= 1900)
constexpr ClientPeersGetResponse_Status ClientPeersGetResponse::STATUS_UNSET;
constexpr ClientPeersGetResponse_Status ClientPeersGetResponse::OK;
constexpr ClientPeersGetResponse_Status ClientPeersGetResponse::ERROR;
constexpr ClientPeersGetResponse_Status ClientPeersGetResponse::Status_MIN;
constexpr ClientPeersGetResponse_Status ClientPeersGetResponse::Status_MAX;
constexpr int ClientPeersGetResponse::Status_ARRAYSIZE;
#endif  // (__cplusplus < 201703) && (!defined(_MSC_VER) || _MSC_VER >= 1900)

// ===================================================================

void ClientPeersGetRequest::InitAsDefaultInstance() {
}
class ClientPeersGetRequest::HasBitSetters {
 public:
};

#if !defined(_MSC_VER) || _MSC_VER >= 1900
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

ClientPeersGetRequest::ClientPeersGetRequest()
  : ::PROTOBUF_NAMESPACE_ID::Message(), _internal_metadata_(nullptr) {
  SharedCtor();
  // @@protoc_insertion_point(constructor:ClientPeersGetRequest)
}
ClientPeersGetRequest::ClientPeersGetRequest(const ClientPeersGetRequest& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      _internal_metadata_(nullptr) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:ClientPeersGetRequest)
}

void ClientPeersGetRequest::SharedCtor() {
}

ClientPeersGetRequest::~ClientPeersGetRequest() {
  // @@protoc_insertion_point(destructor:ClientPeersGetRequest)
  SharedDtor();
}

void ClientPeersGetRequest::SharedDtor() {
}

void ClientPeersGetRequest::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const ClientPeersGetRequest& ClientPeersGetRequest::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_ClientPeersGetRequest_client_5fpeers_2eproto.base);
  return *internal_default_instance();
}


void ClientPeersGetRequest::Clear() {
// @@protoc_insertion_point(message_clear_start:ClientPeersGetRequest)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _internal_metadata_.Clear();
}

#if GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
const char* ClientPeersGetRequest::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      default: {
        if ((tag & 7) == 4 || tag == 0) {
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag, &_internal_metadata_, ptr, ctx);
        CHK_(ptr != nullptr);
        break;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}
#else  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
bool ClientPeersGetRequest::MergePartialFromCodedStream(
    ::PROTOBUF_NAMESPACE_ID::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!PROTOBUF_PREDICT_TRUE(EXPRESSION)) goto failure
  ::PROTOBUF_NAMESPACE_ID::uint32 tag;
  // @@protoc_insertion_point(parse_start:ClientPeersGetRequest)
  for (;;) {
    ::std::pair<::PROTOBUF_NAMESPACE_ID::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
  handle_unusual:
    if (tag == 0) {
      goto success;
    }
    DO_(::PROTOBUF_NAMESPACE_ID::internal::WireFormat::SkipField(
          input, tag, _internal_metadata_.mutable_unknown_fields()));
  }
success:
  // @@protoc_insertion_point(parse_success:ClientPeersGetRequest)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:ClientPeersGetRequest)
  return false;
#undef DO_
}
#endif  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER

void ClientPeersGetRequest::SerializeWithCachedSizes(
    ::PROTOBUF_NAMESPACE_ID::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:ClientPeersGetRequest)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (_internal_metadata_.have_unknown_fields()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::SerializeUnknownFields(
        _internal_metadata_.unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:ClientPeersGetRequest)
}

::PROTOBUF_NAMESPACE_ID::uint8* ClientPeersGetRequest::InternalSerializeWithCachedSizesToArray(
    ::PROTOBUF_NAMESPACE_ID::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:ClientPeersGetRequest)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (_internal_metadata_.have_unknown_fields()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::SerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:ClientPeersGetRequest)
  return target;
}

size_t ClientPeersGetRequest::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:ClientPeersGetRequest)
  size_t total_size = 0;

  if (_internal_metadata_.have_unknown_fields()) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::ComputeUnknownFieldsSize(
        _internal_metadata_.unknown_fields());
  }
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void ClientPeersGetRequest::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:ClientPeersGetRequest)
  GOOGLE_DCHECK_NE(&from, this);
  const ClientPeersGetRequest* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<ClientPeersGetRequest>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:ClientPeersGetRequest)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:ClientPeersGetRequest)
    MergeFrom(*source);
  }
}

void ClientPeersGetRequest::MergeFrom(const ClientPeersGetRequest& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:ClientPeersGetRequest)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

}

void ClientPeersGetRequest::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:ClientPeersGetRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void ClientPeersGetRequest::CopyFrom(const ClientPeersGetRequest& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:ClientPeersGetRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool ClientPeersGetRequest::IsInitialized() const {
  return true;
}

void ClientPeersGetRequest::Swap(ClientPeersGetRequest* other) {
  if (other == this) return;
  InternalSwap(other);
}
void ClientPeersGetRequest::InternalSwap(ClientPeersGetRequest* other) {
  using std::swap;
  _internal_metadata_.Swap(&other->_internal_metadata_);
}

::PROTOBUF_NAMESPACE_ID::Metadata ClientPeersGetRequest::GetMetadata() const {
  return GetMetadataStatic();
}


// ===================================================================

void ClientPeersGetResponse::InitAsDefaultInstance() {
}
class ClientPeersGetResponse::HasBitSetters {
 public:
};

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int ClientPeersGetResponse::kStatusFieldNumber;
const int ClientPeersGetResponse::kPeersFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

ClientPeersGetResponse::ClientPeersGetResponse()
  : ::PROTOBUF_NAMESPACE_ID::Message(), _internal_metadata_(nullptr) {
  SharedCtor();
  // @@protoc_insertion_point(constructor:ClientPeersGetResponse)
}
ClientPeersGetResponse::ClientPeersGetResponse(const ClientPeersGetResponse& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      _internal_metadata_(nullptr),
      peers_(from.peers_) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  status_ = from.status_;
  // @@protoc_insertion_point(copy_constructor:ClientPeersGetResponse)
}

void ClientPeersGetResponse::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_ClientPeersGetResponse_client_5fpeers_2eproto.base);
  status_ = 0;
}

ClientPeersGetResponse::~ClientPeersGetResponse() {
  // @@protoc_insertion_point(destructor:ClientPeersGetResponse)
  SharedDtor();
}

void ClientPeersGetResponse::SharedDtor() {
}

void ClientPeersGetResponse::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const ClientPeersGetResponse& ClientPeersGetResponse::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_ClientPeersGetResponse_client_5fpeers_2eproto.base);
  return *internal_default_instance();
}


void ClientPeersGetResponse::Clear() {
// @@protoc_insertion_point(message_clear_start:ClientPeersGetResponse)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  peers_.Clear();
  status_ = 0;
  _internal_metadata_.Clear();
}

#if GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
const char* ClientPeersGetResponse::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // .ClientPeersGetResponse.Status status = 1;
      case 1: {
        if (static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) != 8) goto handle_unusual;
        ::PROTOBUF_NAMESPACE_ID::uint64 val = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint(&ptr);
        CHK_(ptr);
        set_status(static_cast<::ClientPeersGetResponse_Status>(val));
        break;
      }
      // repeated string peers = 2;
      case 2: {
        if (static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) != 18) goto handle_unusual;
        while (true) {
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParserUTF8(add_peers(), ptr, ctx, "ClientPeersGetResponse.peers");
          CHK_(ptr);
          if (!ctx->DataAvailable(ptr)) break;
          if (::PROTOBUF_NAMESPACE_ID::internal::UnalignedLoad<::PROTOBUF_NAMESPACE_ID::uint8>(ptr) != 18) break;
          ptr += 1;
        }
        break;
      }
      default: {
      handle_unusual:
        if ((tag & 7) == 4 || tag == 0) {
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag, &_internal_metadata_, ptr, ctx);
        CHK_(ptr != nullptr);
        break;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}
#else  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
bool ClientPeersGetResponse::MergePartialFromCodedStream(
    ::PROTOBUF_NAMESPACE_ID::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!PROTOBUF_PREDICT_TRUE(EXPRESSION)) goto failure
  ::PROTOBUF_NAMESPACE_ID::uint32 tag;
  // @@protoc_insertion_point(parse_start:ClientPeersGetResponse)
  for (;;) {
    ::std::pair<::PROTOBUF_NAMESPACE_ID::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // .ClientPeersGetResponse.Status status = 1;
      case 1: {
        if (static_cast< ::PROTOBUF_NAMESPACE_ID::uint8>(tag) == (8 & 0xFF)) {
          int value = 0;
          DO_((::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::ReadPrimitive<
                   int, ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          set_status(static_cast< ::ClientPeersGetResponse_Status >(value));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // repeated string peers = 2;
      case 2: {
        if (static_cast< ::PROTOBUF_NAMESPACE_ID::uint8>(tag) == (18 & 0xFF)) {
          DO_(::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::ReadString(
                input, this->add_peers()));
          DO_(::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
            this->peers(this->peers_size() - 1).data(),
            static_cast<int>(this->peers(this->peers_size() - 1).length()),
            ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::PARSE,
            "ClientPeersGetResponse.peers"));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::PROTOBUF_NAMESPACE_ID::internal::WireFormat::SkipField(
              input, tag, _internal_metadata_.mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:ClientPeersGetResponse)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:ClientPeersGetResponse)
  return false;
#undef DO_
}
#endif  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER

void ClientPeersGetResponse::SerializeWithCachedSizes(
    ::PROTOBUF_NAMESPACE_ID::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:ClientPeersGetResponse)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .ClientPeersGetResponse.Status status = 1;
  if (this->status() != 0) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteEnum(
      1, this->status(), output);
  }

  // repeated string peers = 2;
  for (int i = 0, n = this->peers_size(); i < n; i++) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->peers(i).data(), static_cast<int>(this->peers(i).length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "ClientPeersGetResponse.peers");
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteString(
      2, this->peers(i), output);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::SerializeUnknownFields(
        _internal_metadata_.unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:ClientPeersGetResponse)
}

::PROTOBUF_NAMESPACE_ID::uint8* ClientPeersGetResponse::InternalSerializeWithCachedSizesToArray(
    ::PROTOBUF_NAMESPACE_ID::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:ClientPeersGetResponse)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .ClientPeersGetResponse.Status status = 1;
  if (this->status() != 0) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteEnumToArray(
      1, this->status(), target);
  }

  // repeated string peers = 2;
  for (int i = 0, n = this->peers_size(); i < n; i++) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->peers(i).data(), static_cast<int>(this->peers(i).length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "ClientPeersGetResponse.peers");
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      WriteStringToArray(2, this->peers(i), target);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::SerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:ClientPeersGetResponse)
  return target;
}

size_t ClientPeersGetResponse::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:ClientPeersGetResponse)
  size_t total_size = 0;

  if (_internal_metadata_.have_unknown_fields()) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::ComputeUnknownFieldsSize(
        _internal_metadata_.unknown_fields());
  }
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated string peers = 2;
  total_size += 1 *
      ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(this->peers_size());
  for (int i = 0, n = this->peers_size(); i < n; i++) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
      this->peers(i));
  }

  // .ClientPeersGetResponse.Status status = 1;
  if (this->status() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::EnumSize(this->status());
  }

  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void ClientPeersGetResponse::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:ClientPeersGetResponse)
  GOOGLE_DCHECK_NE(&from, this);
  const ClientPeersGetResponse* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<ClientPeersGetResponse>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:ClientPeersGetResponse)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:ClientPeersGetResponse)
    MergeFrom(*source);
  }
}

void ClientPeersGetResponse::MergeFrom(const ClientPeersGetResponse& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:ClientPeersGetResponse)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  peers_.MergeFrom(from.peers_);
  if (from.status() != 0) {
    set_status(from.status());
  }
}

void ClientPeersGetResponse::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:ClientPeersGetResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void ClientPeersGetResponse::CopyFrom(const ClientPeersGetResponse& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:ClientPeersGetResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool ClientPeersGetResponse::IsInitialized() const {
  return true;
}

void ClientPeersGetResponse::Swap(ClientPeersGetResponse* other) {
  if (other == this) return;
  InternalSwap(other);
}
void ClientPeersGetResponse::InternalSwap(ClientPeersGetResponse* other) {
  using std::swap;
  _internal_metadata_.Swap(&other->_internal_metadata_);
  peers_.InternalSwap(CastToBase(&other->peers_));
  swap(status_, other->status_);
}

::PROTOBUF_NAMESPACE_ID::Metadata ClientPeersGetResponse::GetMetadata() const {
  return GetMetadataStatic();
}


// @@protoc_insertion_point(namespace_scope)
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::ClientPeersGetRequest* Arena::CreateMaybeMessage< ::ClientPeersGetRequest >(Arena* arena) {
  return Arena::CreateInternal< ::ClientPeersGetRequest >(arena);
}
template<> PROTOBUF_NOINLINE ::ClientPeersGetResponse* Arena::CreateMaybeMessage< ::ClientPeersGetResponse >(Arena* arena) {
  return Arena::CreateInternal< ::ClientPeersGetResponse >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
