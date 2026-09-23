#!/usr/bin/env bash
#
# 跨平台编译 examples/ 目录下的所有示例程序
#
# 用法：
#   ./scripts/build_examples_all.sh                                  # 编译所有示例 x 所有默认平台
#   ./scripts/build_examples_all.sh akless_oss_v1_example            # 仅编译指定示例 x 所有默认平台
#
# 环境变量：
#   OUTPUT_DIR  输出根目录，默认为 bin/
#   PLATFORMS   目标平台列表（空格分隔，格式：GOOS/GOARCH），覆盖默认列表
#               示例：PLATFORMS="linux/amd64 darwin/arm64" ./scripts/build_examples_all.sh
#   LDFLAGS     传给 go build 的 -ldflags，默认 "-s -w" 以缩小体积
#   CGO_ENABLED 默认 0（纯静态二进制），可显式设为 1
#
# 产物布局：
#   bin/<goos>_<goarch>/<example>_<goos>_<goarch>[.exe]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

EXAMPLES_DIR="examples"
OUTPUT_DIR="${OUTPUT_DIR:-bin}"
LDFLAGS="${LDFLAGS:--s -w}"
CGO_ENABLED="${CGO_ENABLED:-0}"

# 默认覆盖的平台矩阵，可通过 PLATFORMS 覆盖
DEFAULT_PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

if [[ -n "${PLATFORMS:-}" ]]; then
    # shellcheck disable=SC2206
    PLATFORM_LIST=( ${PLATFORMS} )
else
    PLATFORM_LIST=( "${DEFAULT_PLATFORMS[@]}" )
fi

if [[ ! -d "${EXAMPLES_DIR}" ]]; then
    echo "错误：未找到 ${EXAMPLES_DIR} 目录" >&2
    exit 1
fi

# 收集要编译的示例
declare -a targets=()
if [[ $# -gt 0 ]]; then
    for name in "$@"; do
        file="${EXAMPLES_DIR}/${name%.go}.go"
        if [[ ! -f "${file}" ]]; then
            echo "错误：示例文件不存在: ${file}" >&2
            exit 1
        fi
        targets+=("${file}")
    done
else
    while IFS= read -r -d '' file; do
        targets+=("${file}")
    done < <(find "${EXAMPLES_DIR}" -maxdepth 1 -type f -name '*.go' -print0)
fi

if [[ ${#targets[@]} -eq 0 ]]; then
    echo "未找到任何示例文件可编译"
    exit 0
fi

echo "=== 跨平台编译 examples ==="
echo "项目根目录: ${PROJECT_ROOT}"
echo "输出目录:   ${OUTPUT_DIR}"
echo "CGO_ENABLED: ${CGO_ENABLED}"
echo "LDFLAGS:    ${LDFLAGS}"
echo "示例数量:   ${#targets[@]}"
echo "平台数量:   ${#PLATFORM_LIST[@]} (${PLATFORM_LIST[*]})"
echo

mkdir -p "${OUTPUT_DIR}"

total=0
failed=0
declare -a fail_list=()

for platform in "${PLATFORM_LIST[@]}"; do
    goos="${platform%%/*}"
    goarch="${platform##*/}"
    if [[ -z "${goos}" || -z "${goarch}" || "${goos}" == "${platform}" ]]; then
        echo "跳过非法平台格式: ${platform}" >&2
        continue
    fi

    plat_dir="${OUTPUT_DIR}/${goos}_${goarch}"
    mkdir -p "${plat_dir}"

    echo "--- 平台 ${goos}/${goarch} ---"
    for src in "${targets[@]}"; do
        name="$(basename "${src}" .go)"
        ext=""
        if [[ "${goos}" == "windows" ]]; then
            ext=".exe"
        fi
        out="${plat_dir}/${name}_${goos}_${goarch}${ext}"
        total=$((total + 1))
        printf "  → %-30s -> %s ... " "${src}" "${out}"
        # 每个示例文件以独立 build tag 标注（//go:build example_<x>），必须显式传入对应
        # tag、以 package 模式编译 ./examples，否则 file-mode 不会激活被 tag 排除的文件。
        # 文件名 → tag 的映射：akless_<x>_example.go → example_<x>
        ex="${name#akless_}"          # oss_v1_example
        ex="${ex%_example}"           # oss_v1
        build_tag="example_${ex}"
        if GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED="${CGO_ENABLED}" \
            go build -tags="${build_tag}" -trimpath -ldflags "${LDFLAGS}" -o "${out}" ./examples 2> /tmp/build_err.$$; then
            echo "OK"
        else
            echo "FAILED"
            failed=$((failed + 1))
            fail_list+=("${goos}/${goarch} ${src}")
            sed 's/^/      /' /tmp/build_err.$$ >&2 || true
        fi
        rm -f /tmp/build_err.$$
    done
    echo
done

echo "=== 汇总 ==="
echo "总任务数: ${total}"
echo "成功:     $((total - failed))"
echo "失败:     ${failed}"
if [[ ${failed} -gt 0 ]]; then
    echo "失败列表:"
    for item in "${fail_list[@]}"; do
        echo "  - ${item}"
    done
    exit 1
fi
echo "产物位于: ${OUTPUT_DIR}/<goos>_<goarch>/<example>_<goos>_<goarch>[.exe]"
