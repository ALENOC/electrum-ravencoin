#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_APPIMAGE="$CONTRIB/build-linux/appimage"
DISTDIR="$PROJECT_ROOT/dist"
BUILDDIR="$CONTRIB_APPIMAGE/build/appimage"
APPDIR="$BUILDDIR/electrum.AppDir"
CACHEDIR="$CONTRIB_APPIMAGE/.cache/appimage"
export DLL_TARGET_DIR="$CACHEDIR/dlls"
PIP_CACHE_DIR="$CONTRIB_APPIMAGE/.cache/pip_cache"

. "$CONTRIB"/build_tools_util.sh

git -C "$PROJECT_ROOT" rev-parse 2>/dev/null || fail "Building outside a git clone is not supported."

export GCC_STRIP_BINARIES="1"

# pinned versions
PYTHON_VERSION=3.10.11
PY_VER_MAJOR="3.10"  # as it appears in fs paths
PKG2APPIMAGE_COMMIT="a9c85b7e61a3a883f4a35c41c5decb5af88b6b5d"
APPIMAGETOOL_VERSION="1.9.1"
APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"

VERSION=$(git describe --tags --dirty --always)
APPIMAGE="$DISTDIR/electrum-ravencoin-$VERSION-x86_64.AppImage"

rm -rf "$BUILDDIR"
mkdir -p "$APPDIR" "$CACHEDIR" "$PIP_CACHE_DIR" "$DISTDIR" "$DLL_TARGET_DIR"

# potential leftover from setuptools that might make pip put garbage in binary
rm -rf "$PROJECT_ROOT/build"


info "downloading some dependencies."
download_if_not_exist "$CACHEDIR/functions.sh" "https://raw.githubusercontent.com/AppImage/pkg2appimage/$PKG2APPIMAGE_COMMIT/functions.sh"
verify_hash "$CACHEDIR/functions.sh" "8f67711a28635b07ce539a9b083b8c12d5488c00003d6d726c7b134e553220ed"

# AppImageKit's old release-13 asset was renamed/retired upstream. Pin the
# maintained appimagetool repository to an immutable release and verify the
# downloaded executable before it is ever run.
download_if_not_exist "$CACHEDIR/appimagetool" "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-x86_64.AppImage"
verify_hash "$CACHEDIR/appimagetool" "$APPIMAGETOOL_SHA256"

download_if_not_exist "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz"
verify_hash "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "3c3bc3048303721c904a03eb8326b631e921f11cc3be2988456a42f115daf04c"



info "building python."
tar xf "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" -C "$CACHEDIR"
(
    if [ -f "$CACHEDIR/Python-$PYTHON_VERSION/python" ]; then
        info "python already built, skipping"
        exit 0
    fi
    cd "$CACHEDIR/Python-$PYTHON_VERSION"
    LC_ALL=C export BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%b %d %Y")
    LC_ALL=C export BUILD_TIME=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%H:%M:%S")
    # Patches taken from Ubuntu http://archive.ubuntu.com/ubuntu/pool/main/p/python3.10/python3.10_3.10.7-1ubuntu0.3.debian.tar.xz
    patch -p1 < "$CONTRIB_APPIMAGE/patches/python-3.10-reproducible-buildinfo.diff"
    patch -p1 < "$CONTRIB_APPIMAGE/patches/python-3.10-reproducible-pyc.diff"
    ./configure \
        --cache-file="$CACHEDIR/python.config.cache" \
        --prefix="$APPDIR/usr" \
        --enable-ipv6 \
        --enable-shared \
        -q
    make "-j$CPU_COUNT" -s || fail "Could not build Python"
)
info "installing python."
(
    cd "$CACHEDIR/Python-$PYTHON_VERSION"
    make -s install > /dev/null || fail "Could not install Python"
    # When building in docker on macOS, python builds with .exe extension because the
    # case insensitive file system of macOS leaks into docker. This causes the build
    # to result in a different output on macOS compared to Linux. We simply patch
    # sysconfigdata to remove the extension.
    # Some more info: https://bugs.python.org/issue27631
    sed -i -e 's/\.exe//g' "${APPDIR}/usr/lib/python${PY_VER_MAJOR}"/_sysconfigdata*
)
info "python installed."


if [ -f "$DLL_TARGET_DIR/libsecp256k1.so.2" ]; then
    info "libsecp256k1 already built, skipping"
else
    "$CONTRIB"/make_libsecp256k1.sh || fail "Could not build libsecp"
fi
cp -f "$DLL_TARGET_DIR"/libsecp256k1.so.* "$APPDIR/usr/lib/" || fail "Could not copy libsecp to its destination"


# note: libxcb-util1 is not available in debian 10 (buster), only libxcb-util0. So we build it ourselves.
#       This pkg is needed on some distros for Qt to launch. (see #8011)
info "building libxcb-util1."
XCB_UTIL_VERSION="acf790d7752f36e450d476ad79807d4012ec863b"
# ^ git tag 0.4.0
(
    if [ -f "$CACHEDIR/libxcb-util1/util/src/.libs/libxcb-util.so.1" ]; then
        info "libxcb-util1 already built, skipping"
        exit 0
    fi
    cd "$CACHEDIR"
    mkdir "libxcb-util1"
    cd "libxcb-util1"
    if [ ! -d util ]; then
        git clone --recursive "https://anongit.freedesktop.org/git/xcb/util"
    fi
    cd util
    if ! $(git cat-file -e ${XCB_UTIL_VERSION}) ; then
        info "Could not find requested version $XCB_UTIL_VERSION in local clone; fetching..."
        git fetch --all
        git submodule update
    fi
    git reset --hard
    git clean -dfxq
    git checkout "${XCB_UTIL_VERSION}^{commit}"
    ./autogen.sh
    ./configure --enable-shared
    make "-j$CPU_COUNT" -s || fail "Could not build libxcb-util1"
) || fail "Could build libxcb-util1"
cp "$CACHEDIR/libxcb-util1/util/src/.libs/libxcb-util.so.1" "$APPDIR/usr/lib/libxcb-util.so.1"


info "preparing AppDir."
# Copy libs needed for PyQt5 to run that are *not* included by appimagetool deploy.
# Note that the (important) libxcb-util.so.1 is the one we built above.
for LIB in libxcb-util.so.1 libxcb-icccm.so.4 libxcb-image.so.0 libxcb-keysyms.so.1 libxcb-render-util.so.0 libxcb-xinerama.so.0 libxkbcommon-x11.so.0; do
    if [ "$LIB" == "libxcb-util.so.1" ]; then
        LIB_PATH="$APPDIR/usr/lib/libxcb-util.so.1"
    else
        LIB_PATH=$(ldconfig -p | grep "$LIB" | head -n 1 | awk '{print $NF}')
    fi
    test -f "$LIB_PATH" || fail "Could not find $LIB"
    cp -v "$LIB_PATH" "$APPDIR/usr/lib/"
done

# install packages
cp -r "$PROJECT_ROOT" "$APPDIR/usr/lib/python$PY_VER_MAJOR/site-packages/electrum-source"
python -m pip install --no-dependencies --no-warn-script-location --prefix "$APPDIR/usr" "$PROJECT_ROOT"

# install pyqt
python -m pip install --no-dependencies --no-warn-script-location --prefix "$APPDIR/usr" -r "$CONTRIB/deterministic-build/requirements-pyqt.txt"

# appimage setup
mkdir -p "$APPDIR/usr/share/applications"
cp "$PROJECT_ROOT/electrum-ravencoin.desktop" "$APPDIR/usr/share/applications/electrum-ravencoin.desktop"
mkdir -p "$APPDIR/usr/share/icons/hicolor/128x128/apps"
cp "$PROJECT_ROOT/electrum/gui/icons/electrum-ravencoin.png" "$APPDIR/usr/share/icons/hicolor/128x128/apps/electrum-ravencoin.png"
mkdir -p "$APPDIR/usr/share/metainfo"
cp "$PROJECT_ROOT/org.electrum.electrum.metainfo.xml" "$APPDIR/usr/share/metainfo/org.electrum.electrum.metainfo.xml"

# copy icon + desktop to root as required by AppImage
cp "$APPDIR/usr/share/icons/hicolor/128x128/apps/electrum-ravencoin.png" "$APPDIR/electrum-ravencoin.png"
cp "$APPDIR/usr/share/applications/electrum-ravencoin.desktop" "$APPDIR/electrum-ravencoin.desktop"

# AppRun
cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="$HERE/usr/bin:$PATH"
export LD_LIBRARY_PATH="$HERE/usr/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$HERE/usr/lib/python3.10/site-packages:$PYTHONPATH"
exec "$HERE/usr/bin/electrum-ravencoin" "$@"
EOF
chmod +x "$APPDIR/AppRun"

# appimagetool is itself an AppImage; extract it in Docker where FUSE is not
# available, then invoke its AppRun directly.
chmod +x "$CACHEDIR/appimagetool"
(
    cd "$CACHEDIR"
    rm -rf squashfs-root
    ./appimagetool --appimage-extract >/dev/null
    ARCH=x86_64 ./squashfs-root/AppRun "$APPDIR" "$APPIMAGE"
)

verify_hash "$APPIMAGE" "$(sha256sum "$APPIMAGE" | awk '{print $1}')"
info "Done. Binary is at $APPIMAGE"
