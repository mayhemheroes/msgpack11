#include "fuzzer/FuzzedDataProvider.h"
#include "msgpack11.hpp"

using namespace msgpack11;

MsgPack gen_pack(FuzzedDataProvider& fdp) {
    auto ty = fdp.ConsumeIntegralInRange(0, 12);
    switch(ty) {
        case 0:
            return {fdp.ConsumeBool()};
        case 1:
            return {fdp.ConsumeFloatingPoint<float>()};
        case 2:
            return {fdp.ConsumeFloatingPoint<double>()};
        case 3:
            return {fdp.ConsumeIntegral<int8_t>()};
        case 4:
            return {fdp.ConsumeIntegral<int16_t>()};
        case 5:
            return {fdp.ConsumeIntegral<int32_t>()};
        case 6:
            return {fdp.ConsumeIntegral<int64_t>()};
        case 7:
            return {fdp.ConsumeIntegral<uint8_t>()};
        case 8:
            return {fdp.ConsumeIntegral<uint16_t>()};
        case 9:
            return {fdp.ConsumeIntegral<uint32_t>()};
        case 10:
            return {fdp.ConsumeIntegral<uint64_t>()};
        case 11:
            return {nullptr};
        case 12:
            return {fdp.ConsumeRandomLengthString()};
        default:
            return {};
    }

}
MsgPack::object generate_fuzz_object(FuzzedDataProvider& fdp) {
    MsgPack::object map{};

    for (std::size_t _ = 0; _ < fdp.ConsumeIntegralInRange(0, 1000); ++_) {
        map.insert({gen_pack(fdp), gen_pack(fdp)});
    }

    return map;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    MsgPack msg_obj = generate_fuzz_object(fdp);

    auto msg_bytes = msg_obj.dump();

    std::string err;
    MsgPack::parse(msg_bytes, err);

    return 0;
}
