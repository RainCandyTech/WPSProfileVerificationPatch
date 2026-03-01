#include <Windows.h>
#include <stdexcept>
#include <sstream>
#include <format>
#include <memory>
#include <array>
#include "Detours.h"
#include "KRSAVerifyFileHook.h"
#include "FileUtil.h"
#include "ModuleUtil.h"
#include "PatternUtil.h"
#include "VersionUtil.h"

namespace WPSProfileVerificationPatch {
    bool (*KRSAVerifyFileHook::kRSAVerifyFile)(const std::string& publicKey, const std::string& fileHash, const std::string& fileSignature) = nullptr;

    bool KRSAVerifyFileHook::KRSAVerifyFile(const std::string& publicKey, const std::string& fileHash, const std::string& fileSignature) {
#if defined WP_DEBUG
        std::stringstream ss;
        ss << "KRSAVerifyFile called with parameters:\r\n";
        ss << "Public Key: " << publicKey << "\r\n";
        ss << "File Hash: " << fileHash << "\r\n";
        ss << "File Signature: " << fileSignature << "\r\n";
        ss << "Verification Result: ";
#endif
        // 如果数字签名全部为 0 则通过校验，否则调用原始校验函数
        for (char c : fileSignature) {
            if (c != '0') {
                bool result = kRSAVerifyFile(publicKey, fileHash, fileSignature);
#if defined WP_DEBUG
                ss << (result ? "Passed" : "Failed");
                MessageBoxA(nullptr, ss.str().data(), "KRSAVerifyFile Debug Information", MB_ICONINFORMATION);
#endif
                return result;
            }
        }
#if defined WP_DEBUG
        ss << "Passed (all-zero signature)";
        MessageBoxA(nullptr, ss.str().data(), "KRSAVerifyFile Debug Information", MB_ICONINFORMATION);
#endif
        return true;
    }

    void KRSAVerifyFileHook::LocateTarget() const {
#if defined DETOURS_ARM64
        const std::array<uint16_t, 20> anchor = { 0x00, 0xD0, 0xFFFF, 0xFFFF, 0xFFFF, 0x91, 0xFFFF, 0xFFFF, 0x00, 0xD0, 0xFFFF, 0xFFFF, 0xFFFF, 0x91, 0xFFFF, 0x5A, 0x00, 0xA9 };
        const std::array<uint16_t, 4> prologue = { 0xFD, 0xFFFF, 0xFFFF, 0xA9 };
#elif defined DETOURS_X64
        const std::array<uint16_t, 21> anchor = { 0x4C, 0x8D, 0x3D, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x4C, 0x89, 0x3F, 0x4C, 0x8D, 0x25, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x4C, 0x89, 0x67, 0x08 };
        const std::array<uint16_t, 3> prologue = { 0x40, 0x53, 0x56 };
#elif defined DETOURS_X86
        const std::array<uint16_t, 25> anchor = { 0xC7, 0x06, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xC7, 0x46, 0x04, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xEB, 0x02, 0x33, 0xF6, 0x83, 0x7F, 0x14, 0x10, 0xC6, 0x45, 0xFC, 0x00 };
        const std::array<uint16_t, 3> prologue = { 0x55, 0x8B, 0xEC };
#else
#error "Unsupported architecture"
#endif
        std::wstring fileName = ModuleUtil::GetFileNameW(nullptr);
        std::unique_ptr<const uint8_t[]> versionInfoData = VersionUtil::GetVersionInfoDataW(fileName);
        std::optional<std::span<const uint8_t>> translation = VersionUtil::QueryVersionInfoValueW(versionInfoData, L"\\VarFileInfo\\Translation");
        if (!translation.has_value()) {
            // 没有找到 Translation，不进行 Hook
            throw std::runtime_error("Failed to find Translation in version info");
        }
        uint16_t langId = *reinterpret_cast<const uint16_t*>(translation->data());
        uint16_t codePage = *reinterpret_cast<const uint16_t*>(translation->data() + 2);
        std::optional<std::span<const uint8_t>> productName = VersionUtil::QueryVersionInfoValueW(versionInfoData, std::format(L"\\StringFileInfo\\{:04x}{:04x}\\ProductName", langId, codePage));
        if (!productName.has_value() || productName->size() != 11 || std::memcmp(productName->data(), L"WPS Office", 22) != 0) {
            // ProductName 不是 WPS Office，不进行 Hook
            throw std::runtime_error("ProductName is not WPS Office");
        }
        std::span<const uint8_t> region;
#if defined WP_PACKET
        std::optional<std::span<const uint8_t>> internalName = VersionUtil::QueryVersionInfoValueW(versionInfoData, std::format(L"\\StringFileInfo\\{:04x}{:04x}\\InternalName", langId, codePage));
        if (internalName.has_value() && internalName->size() >= 8 && std::memcmp(internalName->data(), L"KPacket", 14) == 0) {
            // InternalName 以 KPacket 开头表明这是安装程序，要在主模块中查找特征码
            HMODULE module = ModuleUtil::GetHandleW(std::nullopt);
            region = ModuleUtil::GetMemoryRegion();
        } else {
            throw std::runtime_error("KRSAVerifyFileHook can only be installed in the installer module");
        }
#elif defined WP_MAIN
        HMODULE module = ModuleUtil::GetSelfHandle();
        std::wstring krtPath = ModuleUtil::GetBasePathW(module) + L"krt.dll";
        if (FileUtil::IsFileExistsW(krtPath)) {
            // 本模块目录下存在 krt.dll 表明这是主程序，要在 krt.dll 中查找特征码
            // 本模块加载时 krt.dll 还未被加载，要主动加载本模块同目录下的 krt.dll
            HMODULE krtModule = LoadLibraryW(krtPath.data());
            if (!krtModule) {
                throw std::runtime_error("Failed to load krt.dll");
            }
            region = ModuleUtil::GetMemoryRegion(krtModule);
        } else {
            throw std::runtime_error("KRSAVerifyFileHook can only be installed in the main module with krt.dll loaded");
        }
#else
#error "Either WP_PACKET or WP_MAIN must be defined"
#endif
#if defined WP_DEBUG
        constexpr size_t maxMatches = 2;
#else
        constexpr size_t maxMatches = 1;
#endif
        std::vector<const uint8_t*> anchors = PatternUtil::FindPattern(region, anchor, 0, false, maxMatches);
        if (anchors.size() == 0) {
            throw std::runtime_error("Failed to find KRSAVerifyFile anchor");
        }
#if defined WP_DEBUG
        if (anchors.size() > 1) {
            throw std::runtime_error("Multiple KRSAVerifyFile anchors found");
        }
#endif
        std::vector<const uint8_t*> prologues = PatternUtil::FindPattern(region, prologue, anchors[0] - region.data(), true, 1);
        if (prologues.size() == 0) {
            throw std::runtime_error("Failed to find KRSAVerifyFile prologue");
        }
        kRSAVerifyFile = reinterpret_cast<decltype(kRSAVerifyFile)>(prologues[0]);
    }

    PVOID* KRSAVerifyFileHook::GetOriginalPointer() const {
        return reinterpret_cast<PVOID*>(&kRSAVerifyFile);
    }

    PVOID KRSAVerifyFileHook::GetDetourFunction() const {
        return reinterpret_cast<PVOID>(KRSAVerifyFile);
    }

    const char* KRSAVerifyFileHook::GetName() const {
        return "KRSAVerifyFile";
    }
}
