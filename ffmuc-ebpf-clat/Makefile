include $(TOPDIR)/rules.mk

PKG_NAME:=ffmuc-ebpf-clat
PKG_VERSION:=1
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(TOPDIR)/../package/gluon.mk

# TODO: Update Depends
define Package/$(PKG_NAME)
  TITLE:=Adds eBPF stuff for testing
  DEPENDS:=+libbpf +bpf-headers
  EXTRA_DEPENDS:=kmod-sched-bpf
endef

define Build/Compile
	$(call Build/Compile/Default,)
endef

define Package/$(PKG_NAME)/install
	$(Gluon/Build/Install)
	$(INSTALL_DIR) $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/clat $(1)/usr/sbin/ebpf-clat
endef

$(eval $(call BuildPackageGluon,$(PKG_NAME)))
