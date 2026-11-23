include $(TOPDIR)/rules.mk

PKG_NAME:=ffmuc-dhcp-ap-controllers
PKG_VERSION:=1
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(TOPDIR)/../package/gluon.mk

define Package/$(PKG_NAME)
  TITLE:=Tells UniFi and Omada access points the address of their controller
  DEPENDS:=+gluon-core
endef

$(eval $(call BuildPackageGluon,$(PKG_NAME)))
