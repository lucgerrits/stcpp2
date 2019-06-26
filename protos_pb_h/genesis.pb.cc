// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: genesis.proto

#include "genesis.pb.h"

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
extern PROTOBUF_INTERNAL_EXPORT_batch_2eproto ::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<1> scc_info_Batch_batch_2eproto;
class GenesisDataDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<GenesisData> _instance;
} _GenesisData_default_instance_;
static void InitDefaultsscc_info_GenesisData_genesis_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::_GenesisData_default_instance_;
    new (ptr) ::GenesisData();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::GenesisData::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<1> scc_info_GenesisData_genesis_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 1, InitDefaultsscc_info_GenesisData_genesis_2eproto}, {
      &scc_info_Batch_batch_2eproto.base,}};

static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_genesis_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_genesis_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_genesis_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_genesis_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::GenesisData, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::GenesisData, batches_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::GenesisData)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::_GenesisData_default_instance_),
};

const char descriptor_table_protodef_genesis_2eproto[] =
  "\n\rgenesis.proto\032\013batch.proto\"&\n\013GenesisD"
  "ata\022\027\n\007batches\030\001 \003(\0132\006.BatchB&\n\025sawtooth"
  ".sdk.protobufP\001Z\013genesis_pb2b\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_genesis_2eproto_deps[1] = {
  &::descriptor_table_batch_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase*const descriptor_table_genesis_2eproto_sccs[1] = {
  &scc_info_GenesisData_genesis_2eproto.base,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_genesis_2eproto_once;
static bool descriptor_table_genesis_2eproto_initialized = false;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_genesis_2eproto = {
  &descriptor_table_genesis_2eproto_initialized, descriptor_table_protodef_genesis_2eproto, "genesis.proto", 116,
  &descriptor_table_genesis_2eproto_once, descriptor_table_genesis_2eproto_sccs, descriptor_table_genesis_2eproto_deps, 1, 1,
  schemas, file_default_instances, TableStruct_genesis_2eproto::offsets,
  file_level_metadata_genesis_2eproto, 1, file_level_enum_descriptors_genesis_2eproto, file_level_service_descriptors_genesis_2eproto,
};

// Force running AddDescriptors() at dynamic initialization time.
static bool dynamic_init_dummy_genesis_2eproto = (  ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptors(&descriptor_table_genesis_2eproto), true);

// ===================================================================

void GenesisData::InitAsDefaultInstance() {
}
class GenesisData::HasBitSetters {
 public:
};

void GenesisData::clear_batches() {
  batches_.Clear();
}
#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int GenesisData::kBatchesFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

GenesisData::GenesisData()
  : ::PROTOBUF_NAMESPACE_ID::Message(), _internal_metadata_(nullptr) {
  SharedCtor();
  // @@protoc_insertion_point(constructor:GenesisData)
}
GenesisData::GenesisData(const GenesisData& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      _internal_metadata_(nullptr),
      batches_(from.batches_) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:GenesisData)
}

void GenesisData::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_GenesisData_genesis_2eproto.base);
}

GenesisData::~GenesisData() {
  // @@protoc_insertion_point(destructor:GenesisData)
  SharedDtor();
}

void GenesisData::SharedDtor() {
}

void GenesisData::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const GenesisData& GenesisData::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_GenesisData_genesis_2eproto.base);
  return *internal_default_instance();
}


void GenesisData::Clear() {
// @@protoc_insertion_point(message_clear_start:GenesisData)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  batches_.Clear();
  _internal_metadata_.Clear();
}

#if GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
const char* GenesisData::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // repeated .Batch batches = 1;
      case 1: {
        if (static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) != 10) goto handle_unusual;
        while (true) {
          ptr = ctx->ParseMessage(add_batches(), ptr);
          CHK_(ptr);
          if (!ctx->DataAvailable(ptr)) break;
          if (::PROTOBUF_NAMESPACE_ID::internal::UnalignedLoad<::PROTOBUF_NAMESPACE_ID::uint8>(ptr) != 10) break;
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
bool GenesisData::MergePartialFromCodedStream(
    ::PROTOBUF_NAMESPACE_ID::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!PROTOBUF_PREDICT_TRUE(EXPRESSION)) goto failure
  ::PROTOBUF_NAMESPACE_ID::uint32 tag;
  // @@protoc_insertion_point(parse_start:GenesisData)
  for (;;) {
    ::std::pair<::PROTOBUF_NAMESPACE_ID::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .Batch batches = 1;
      case 1: {
        if (static_cast< ::PROTOBUF_NAMESPACE_ID::uint8>(tag) == (10 & 0xFF)) {
          DO_(::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::ReadMessage(
                input, add_batches()));
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
  // @@protoc_insertion_point(parse_success:GenesisData)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:GenesisData)
  return false;
#undef DO_
}
#endif  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER

void GenesisData::SerializeWithCachedSizes(
    ::PROTOBUF_NAMESPACE_ID::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:GenesisData)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .Batch batches = 1;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->batches_size()); i < n; i++) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteMessageMaybeToArray(
      1,
      this->batches(static_cast<int>(i)),
      output);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::SerializeUnknownFields(
        _internal_metadata_.unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:GenesisData)
}

::PROTOBUF_NAMESPACE_ID::uint8* GenesisData::InternalSerializeWithCachedSizesToArray(
    ::PROTOBUF_NAMESPACE_ID::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:GenesisData)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .Batch batches = 1;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->batches_size()); i < n; i++) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessageToArray(
        1, this->batches(static_cast<int>(i)), target);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::SerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:GenesisData)
  return target;
}

size_t GenesisData::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:GenesisData)
  size_t total_size = 0;

  if (_internal_metadata_.have_unknown_fields()) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::ComputeUnknownFieldsSize(
        _internal_metadata_.unknown_fields());
  }
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .Batch batches = 1;
  {
    unsigned int count = static_cast<unsigned int>(this->batches_size());
    total_size += 1UL * count;
    for (unsigned int i = 0; i < count; i++) {
      total_size +=
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
          this->batches(static_cast<int>(i)));
    }
  }

  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void GenesisData::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:GenesisData)
  GOOGLE_DCHECK_NE(&from, this);
  const GenesisData* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<GenesisData>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:GenesisData)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:GenesisData)
    MergeFrom(*source);
  }
}

void GenesisData::MergeFrom(const GenesisData& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:GenesisData)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  batches_.MergeFrom(from.batches_);
}

void GenesisData::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:GenesisData)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void GenesisData::CopyFrom(const GenesisData& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:GenesisData)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool GenesisData::IsInitialized() const {
  return true;
}

void GenesisData::Swap(GenesisData* other) {
  if (other == this) return;
  InternalSwap(other);
}
void GenesisData::InternalSwap(GenesisData* other) {
  using std::swap;
  _internal_metadata_.Swap(&other->_internal_metadata_);
  CastToBase(&batches_)->InternalSwap(CastToBase(&other->batches_));
}

::PROTOBUF_NAMESPACE_ID::Metadata GenesisData::GetMetadata() const {
  return GetMetadataStatic();
}


// @@protoc_insertion_point(namespace_scope)
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::GenesisData* Arena::CreateMaybeMessage< ::GenesisData >(Arena* arena) {
  return Arena::CreateInternal< ::GenesisData >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
