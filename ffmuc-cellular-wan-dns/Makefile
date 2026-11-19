include $(TOPDIR)/rules.mk

PKG_NAME:=ffmuc-cellular-wan-dns
PKG_VERSION:=1
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(TOPDIR)/../package/gluon.mk

define Package/$(PKG_NAME)
  TITLE:=Keeps the WAN DNS servers of gluon-wan-dnsmasq on cellular uplinks
  DEPENDS:=+gluon-core +gluon-wan-dnsmasq
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/ffmuc-cellular-wan-dns
endef

$(eval $(call BuildPackageGluon,$(PKG_NAME)))
