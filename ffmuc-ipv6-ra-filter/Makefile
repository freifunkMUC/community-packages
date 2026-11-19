include $(TOPDIR)/rules.mk

PKG_NAME:=ffmuc-ipv6-ra-filter
PKG_VERSION:=1
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(TOPDIR)/../package/gluon.mk

define Package/$(PKG_NAME)
  TITLE:=Accept router advertisements only from the selected batman-adv gateway
  DEPENDS:=+gluon-ebtables +libgluonutil +libbatadv +libnl-tiny +ip6tables +kmod-ipt-core
endef

MAKE_VARS += \
	LIBNL_NAME="libnl-tiny" \
	LIBNL_GENL_NAME="libnl-tiny"

define Package/$(PKG_NAME)/install
	$(Gluon/Build/Install)

	$(INSTALL_DIR) $(1)/lib/gluon/ffmuc-ipv6-ra-filter
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ra-goodbye $(1)/lib/gluon/ffmuc-ipv6-ra-filter/
endef

$(eval $(call BuildPackageGluon,$(PKG_NAME)))
