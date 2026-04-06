/*
 * 86Box    A hypervisor and IBM PC system emulator that specializes in
 *          running old operating systems and software designed for IBM
 *          PC systems and compatibles from 1981 through fairly recent
 *          system designs based on the PCI bus.
 *
 *          This file is part of the 86Box distribution.
 *
 *          Network devices configuration UI module.
 *
 * Authors: Joakim L. Gilje <jgilje@jgilje.net>
 *
 *          Copyright 2021 Joakim L. Gilje
 */

#include <cstdint>
#include <cstdio>

#ifdef __APPLE__
#    include <ifaddrs.h>
#    include <net/if.h>
#    include <netinet/in.h>
#endif

#include <QMessageBox>
#include <QSignalBlocker>
#include <QHostAddress>
#include <QAbstractSocket>

extern "C" {
#include <86box/86box.h>
#include <86box/device.h>
#include <86box/machine.h>
#include <86box/timer.h>
#include <86box/thread.h>
#include <86box/network.h>
}

#include "qt_models_common.hpp"
#include "qt_deviceconfig.hpp"

#include "qt_defs.hpp"

#include "qt_settings_completer.hpp"

#include "qt_settingsnetwork.hpp"
#include "ui_qt_settingsnetwork.h"

#ifdef __APPLE__
static inline bool
is_vmnet_type(int net_type)
{
    return (net_type == NET_TYPE_VMNET_NAT) ||
           (net_type == NET_TYPE_VMNET_HOST) ||
           (net_type == NET_TYPE_VMNET_BRIDGE) ||
           (net_type == NET_TYPE_VMNET_PUB);
}

static inline bool
vmnet_type_uses_interface(int net_type)
{
    return (net_type == NET_TYPE_VMNET_BRIDGE) ||
           (net_type == NET_TYPE_VMNET_PUB);
}

static inline bool
is_legacy_vmnet_host_device_name(const char *host_dev_name)
{
    return !strcmp(host_dev_name, "vmnet-shared") ||
           !strcmp(host_dev_name, "vmnet-host") ||
           !strcmp(host_dev_name, "vmnet-bridged") ||
           !strcmp(host_dev_name, "vmnet-published") ||
           !strcmp(host_dev_name, "vmnet-bridge") ||
           !strcmp(host_dev_name, "vmnet-pub");
}

static bool
vmnet_host_interface_is_valid(const char *ifname)
{
    if ((ifname == nullptr) || (ifname[0] == '\0'))
        return false;

    struct ifaddrs *ifaddr = nullptr;
    bool            valid  = false;

    if (getifaddrs(&ifaddr) != 0)
        return false;

    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if ((ifa->ifa_name == nullptr) || (ifa->ifa_addr == nullptr))
            continue;
        if (strcmp(ifa->ifa_name, ifname) != 0)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if ((ifa->ifa_flags & IFF_UP) == 0)
            continue;
        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;

        valid = true;
        break;
    }

    freeifaddrs(ifaddr);
    return valid;
}
#endif

void
SettingsNetwork::enableElements(Ui::SettingsNetwork *ui)
{
    for (int i = 0; i < NET_CARD_MAX; ++i) {
        net_card_cfg_changed[i] = 0;

        auto *nic_cbox      = findChild<QComboBox *>(QString("comboBoxNIC%1").arg(i + 1));
        auto *net_type_cbox = findChild<QComboBox *>(QString("comboBoxNet%1").arg(i + 1));

        auto *intf_label = findChild<QLabel *>(QString("labelIntf%1").arg(i + 1));
        auto *intf_cbox  = findChild<QComboBox *>(QString("comboBoxIntf%1").arg(i + 1));

        auto *conf_btn = findChild<QPushButton *>(QString("pushButtonConf%1").arg(i + 1));
        // auto *net_type_conf_btn      = findChild<QPushButton *>(QString("pushButtonNetTypeConf%1").arg(i + 1));

        auto *vde_socket_label = findChild<QLabel *>(QString("labelSocketVDENIC%1").arg(i + 1));
        auto *socket_line      = findChild<QLineEdit *>(QString("socketVDENIC%1").arg(i + 1));

        auto *bridge_label = findChild<QLabel *>(QString("labelBridgeTAPNIC%1").arg(i + 1));
        auto *bridge_line  = findChild<QLineEdit *>(QString("bridgeTAPNIC%1").arg(i + 1));

        auto *option_list_label = findChild<QLabel *>(QString("labelOptionList%1").arg(i + 1));
        auto *option_list_line  = findChild<QWidget *>(QString("lineOptionList%1").arg(i + 1));

        // Shared secret
        auto *secret_label = findChild<QLabel *>(QString("labelSecret%1").arg(i + 1));
        auto *secret_value = findChild<QLineEdit *>(QString("secretSwitch%1").arg(i + 1));

        // Promiscuous option
        auto *promisc_label = findChild<QLabel *>(QString("labelPromisc%1").arg(i + 1));
        auto *promisc_value = findChild<QCheckBox *>(QString("boxPromisc%1").arg(i + 1));

        // Remote switch hostname
        auto *hostname_label = findChild<QLabel *>(QString("labelHostname%1").arg(i + 1));
        auto *hostname_value = findChild<QLineEdit *>(QString("hostnameSwitch%1").arg(i + 1));

        bridge_line->setEnabled((net_type_cbox->currentData().toInt() == NET_TYPE_TAP)
#ifdef __APPLE__
                                || (net_type_cbox->currentData().toInt() == NET_TYPE_VMNET_NAT)
#endif
        );
        int current_net_type = net_type_cbox->currentData().toInt();
        intf_cbox->setEnabled(current_net_type == NET_TYPE_PCAP
#ifdef __APPLE__
                              || current_net_type == NET_TYPE_VMNET_BRIDGE
                              || current_net_type == NET_TYPE_VMNET_PUB
#endif
        );
        conf_btn->setEnabled(network_card_has_config(nic_cbox->currentData().toInt()));
        // net_type_conf_btn->setEnabled(network_type_has_config(netType));

        // NEW STUFF
        // Make all options invisible by default

        secret_label->setVisible(false);
        secret_value->setVisible(false);

        // Promiscuous options
        promisc_label->setVisible(false);
        promisc_value->setVisible(false);

        // Hostname
        hostname_label->setVisible(false);
        hostname_value->setVisible(false);

        // Option list label and line
        option_list_label->setVisible(false);
        option_list_line->setVisible(false);

        // VDE
        vde_socket_label->setVisible(false);
        socket_line->setVisible(false);

        // TAP
        bridge_label->setVisible(false);
        bridge_line->setVisible(false);

        // PCAP
        intf_cbox->setVisible(false);
        intf_label->setVisible(false);

        // Don't enable anything unless there's a nic selected
        if (nic_cbox->currentData().toInt() != 0) {
            // Then only enable as needed based on network type
            switch (net_type_cbox->currentData().toInt()) {
#ifdef HAS_VDE
                case NET_TYPE_VDE:
                    // option_list_label->setText("VDE Options");
                    option_list_label->setVisible(true);
                    option_list_line->setVisible(true);

                    vde_socket_label->setVisible(true);
                    socket_line->setVisible(true);
                    break;
#endif

                case NET_TYPE_PCAP:
                    // option_list_label->setText("PCAP Options");
                    option_list_label->setVisible(true);
                    option_list_line->setVisible(true);

                    intf_cbox->setVisible(true);
                    intf_label->setVisible(true);
                    intf_label->setText(tr("Interface"));
                    break;

#ifdef __APPLE__
                case NET_TYPE_VMNET_BRIDGE:
                case NET_TYPE_VMNET_PUB:
                    option_list_label->setVisible(true);
                    option_list_line->setVisible(true);

                    intf_cbox->setVisible(true);
                    intf_label->setVisible(true);
                    intf_label->setText(tr("Host interface"));
                    break;

                case NET_TYPE_VMNET_NAT:
                    option_list_label->setVisible(true);
                    option_list_line->setVisible(true);

                    bridge_label->setVisible(true);
                    bridge_line->setVisible(true);
                    bridge_label->setText(tr("Guest IPv4"));
                    break;

                case NET_TYPE_VMNET_HOST:
                    break;
#endif

#if defined(__unix__) || defined(__APPLE__)
                case NET_TYPE_TAP:
                    // option_list_label->setText("TAP Options");
                    option_list_label->setVisible(true);
                    option_list_line->setVisible(true);

                    bridge_label->setVisible(true);
                    bridge_line->setVisible(true);
                    break;
#endif

                case NET_TYPE_NLSWITCH:
                    // option_list_label->setText("Local Switch Options");
                    option_list_label->setVisible(true);
                    option_list_line->setVisible(true);

                    // Shared secret
                    secret_label->setVisible(true);
                    secret_value->setVisible(true);

                    // Promiscuous options
                    promisc_label->setVisible(true);
                    promisc_value->setVisible(true);
                    break;

                case NET_TYPE_NRSWITCH:
                    // option_list_label->setText("Remote Switch Options");
                    option_list_label->setVisible(true);
                    option_list_line->setVisible(true);

                    // Shared secret
                    secret_label->setVisible(true);
                    secret_value->setVisible(true);

                    // Hostname
                    hostname_label->setVisible(true);
                    hostname_value->setVisible(true);
                    break;

                case NET_TYPE_SLIRP:
                default:
                    break;
            }
        }
    }
}

static void
populateInterfaceCombo(SettingsNetwork *self, int slot, int net_type, const QString &currentDevice)
{
    auto *cbox = self->findChild<QComboBox *>(QString("comboBoxIntf%1").arg(slot + 1));
    if (cbox == nullptr)
        return;

    QSignalBlocker blocker(cbox);

    auto *model       = cbox->model();
    int   removeRows  = model->rowCount();
    int   selectedRow = 0;

    for (int c = 0; c < network_ndev; c++) {
#ifdef __APPLE__
        if (vmnet_type_uses_interface(net_type) && !vmnet_host_interface_is_valid(network_devs[c].device))
            continue;
#endif
        int row = Models::AddEntry(model, QObject::tr(network_devs[c].description), c);
        if (QString(network_devs[c].device) == currentDevice)
            selectedRow = row - removeRows;
    }

    model->removeRows(0, removeRows);

    if (model->rowCount() <= 0) {
        cbox->setCurrentIndex(-1);
        return;
    }

    if (selectedRow < 0)
        selectedRow = 0;
    if (selectedRow >= model->rowCount())
        selectedRow = 0;

    cbox->setCurrentIndex(selectedRow);
}

SettingsNetwork::SettingsNetwork(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::SettingsNetwork)
{
    ui->setupUi(this);

    for (int i = 0; i < NET_CARD_MAX; i++) {
        sc[i]                           = new SettingsCompleter(findChild<QComboBox *>(QString("comboBoxNIC%1").arg(i + 1)), nullptr);
        scDevice[i]                     = new SettingsCompleter(findChild<QComboBox *>(QString("comboBoxIntf%1").arg(i + 1)), nullptr);
    }

    onCurrentMachineChanged(machine);
    enableElements(ui);
    for (int i = 0; i < NET_CARD_MAX; i++) {
        auto *nic_cbox      = findChild<QComboBox *>(QString("comboBoxNIC%1").arg(i + 1));
        auto *net_type_cbox = findChild<QComboBox *>(QString("comboBoxNet%1").arg(i + 1));
        auto *intf_cbox     = findChild<QComboBox *>(QString("comboBoxIntf%1").arg(i + 1));
        connect(nic_cbox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SettingsNetwork::on_comboIndexChanged);
        connect(net_type_cbox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SettingsNetwork::on_comboIndexChanged);
        connect(intf_cbox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SettingsNetwork::on_comboIndexChanged);
    }
}

SettingsNetwork::~SettingsNetwork()
{
    for (int i = 0; i < NET_CARD_MAX; i++) {
        delete sc[i];
        delete scDevice[i];
    }

    delete ui;
}

int
SettingsNetwork::changed()
{
    int has_changed = 0;

    for (int i = 0; i < NET_CARD_MAX; ++i) {
        auto *cbox = findChild<QComboBox *>(QString("comboBoxNIC%1").arg(i + 1));
#ifdef HAS_VDE
        auto *socket_line = findChild<QLineEdit *>(QString("socketVDENIC%1").arg(i + 1));
#endif
#if defined(__unix__) || defined(__APPLE__)
        auto *bridge_line = findChild<QLineEdit *>(QString("bridgeTAPNIC%1").arg(i + 1));
#endif
        has_changed                 |= (net_cards_conf[i].device_num != cbox->currentData().toInt());
        has_changed                 |= net_card_cfg_changed[i];
        cbox                         = findChild<QComboBox *>(QString("comboBoxNet%1").arg(i + 1));
        int current_net_type        = cbox->currentData().toInt();
        has_changed                 |= (net_cards_conf[i].net_type != current_net_type);
        cbox                         = findChild<QComboBox *>(QString("comboBoxIntf%1").arg(i + 1));
        auto *hostname_value         = findChild<QLineEdit *>(QString("hostnameSwitch%1").arg(i + 1));
        auto *promisc_value          = findChild<QCheckBox *>(QString("boxPromisc%1").arg(i + 1));
        auto *secret_value           = findChild<QLineEdit *>(QString("secretSwitch%1").arg(i + 1));
        char  temp_host_dev_name[128];
        char  temp_secret[256];
        char  temp_nrs_hostname[128];
        char  temp_vmnet_guest_ip[16];
        memset(temp_host_dev_name, '\0', sizeof(temp_host_dev_name));
        memcpy(temp_secret, net_cards_conf[i].secret, 256);
        memcpy(temp_nrs_hostname, net_cards_conf[i].nrs_hostname, 128);
        memcpy(temp_vmnet_guest_ip, net_cards_conf[i].vmnet_guest_ip, 16);
        if (current_net_type == NET_TYPE_PCAP)
            strncpy(temp_host_dev_name, network_devs[cbox->currentData().toInt()].device, sizeof(temp_host_dev_name) - 1);
#ifdef __APPLE__
        else if (vmnet_type_uses_interface(current_net_type))
            strncpy(temp_host_dev_name, network_devs[cbox->currentData().toInt()].device, sizeof(temp_host_dev_name) - 1);
        else if (is_vmnet_type(current_net_type))
            strncpy(temp_host_dev_name, "none", sizeof(temp_host_dev_name) - 1);

        if (current_net_type == NET_TYPE_VMNET_NAT) {
            memset(temp_vmnet_guest_ip, '\0', sizeof(temp_vmnet_guest_ip));
            strncpy(temp_vmnet_guest_ip, bridge_line->text().toUtf8().constData(), sizeof(temp_vmnet_guest_ip) - 1);
        }
#endif
#ifdef HAS_VDE
        else if (net_cards_conf[i].net_type == NET_TYPE_VDE)
            strncpy(temp_host_dev_name, socket_line->text().toUtf8().constData(), sizeof(temp_host_dev_name) - 1);
#endif
#if defined(__unix__) || defined(__APPLE__)
        else if (net_cards_conf[i].net_type == NET_TYPE_TAP)
            strncpy(temp_host_dev_name, bridge_line->text().toUtf8().constData(), sizeof(temp_host_dev_name) - 1);
#endif
        else if (net_cards_conf[i].net_type == NET_TYPE_NRSWITCH) {
            memset(temp_nrs_hostname, '\0', sizeof(temp_nrs_hostname));
            strncpy(temp_nrs_hostname, hostname_value->text().toUtf8().constData(), sizeof(temp_nrs_hostname) - 1);
            memset(temp_secret, '\0', sizeof(temp_secret));
            strncpy(temp_secret, secret_value->text().toUtf8().constData(), sizeof(temp_secret) - 1);
        } else if (net_cards_conf[i].net_type == NET_TYPE_NLSWITCH) {
            has_changed |= (net_cards_conf[i].promisc_mode != promisc_value->isChecked());
            memset(temp_secret, '\0', sizeof(temp_secret));
            strncpy(temp_secret, secret_value->text().toUtf8().constData(), sizeof(temp_secret) - 1);
        }
        if (temp_host_dev_name[0] == 0x00)
            strncpy(temp_host_dev_name, "none", 5);
        temp_host_dev_name[sizeof(temp_host_dev_name) - 1] = 0x00;
        has_changed |= strcmp(temp_host_dev_name, net_cards_conf[i].host_dev_name);
        has_changed |= strcmp(temp_secret,        net_cards_conf[i].secret);
        has_changed |= strcmp(temp_nrs_hostname,  net_cards_conf[i].nrs_hostname);
        has_changed |= strcmp(temp_vmnet_guest_ip, net_cards_conf[i].vmnet_guest_ip);
    }

    return has_changed ? (SETTINGS_CHANGED | SETTINGS_REQUIRE_HARD_RESET) : 0;
}

void
SettingsNetwork::restore()
{
}

void
SettingsNetwork::save()
{
#ifdef __APPLE__
    for (int i = 0; i < NET_CARD_MAX; ++i) {
        auto *net_type_cbox = findChild<QComboBox *>(QString("comboBoxNet%1").arg(i + 1));
        int   current_net_type = net_type_cbox->currentData().toInt();

        if (vmnet_type_uses_interface(current_net_type)) {
            auto *intf_cbox = findChild<QComboBox *>(QString("comboBoxIntf%1").arg(i + 1));

            if ((intf_cbox == nullptr) || (intf_cbox->currentIndex() < 0) ||
                !intf_cbox->currentData().isValid()) {
                QMessageBox::warning(this,
                                     tr("Network Configuration Error"),
                                     tr("Adapter %1 requires a host interface to be selected.").arg(i + 1));
                return;
            }

            const int dev_idx = intf_cbox->currentData().toInt();
            if ((dev_idx < 0) || (dev_idx >= network_ndev) ||
                !vmnet_host_interface_is_valid(network_devs[dev_idx].device)) {
                QMessageBox::warning(this,
                                     tr("Network Configuration Error"),
                                     tr("Adapter %1 must use a host interface with an active IPv4 address.").arg(i + 1));
                return;
            }
        }
    }
#endif

#ifdef __APPLE__
    for (int i = 0; i < NET_CARD_MAX; ++i) {
        auto *net_type_cbox = findChild<QComboBox *>(QString("comboBoxNet%1").arg(i + 1));
        int   current_net_type = net_type_cbox->currentData().toInt();

        if (current_net_type == NET_TYPE_VMNET_NAT) {
            auto *guest_ip_line = findChild<QLineEdit *>(QString("bridgeTAPNIC%1").arg(i + 1));
            const QString guest_ip_text = guest_ip_line ? guest_ip_line->text().trimmed() : QString();

            if (!guest_ip_text.isEmpty()) {
                QHostAddress addr;
                if (!addr.setAddress(guest_ip_text) || (addr.protocol() != QAbstractSocket::IPv4Protocol)) {
                    QMessageBox::warning(this,
                                         tr("Network Configuration Error"),
                                         tr("Adapter %1 has an invalid Guest IPv4 address.").arg(i + 1));
                    return;
                }
            }
        }
    }
#endif

    for (int i = 0; i < NET_CARD_MAX; ++i) {
        auto *cbox = findChild<QComboBox *>(QString("comboBoxNIC%1").arg(i + 1));
#ifdef HAS_VDE
        auto *socket_line = findChild<QLineEdit *>(QString("socketVDENIC%1").arg(i + 1));
#endif
#if defined(__unix__) || defined(__APPLE__)
        auto *bridge_line = findChild<QLineEdit *>(QString("bridgeTAPNIC%1").arg(i + 1));
#endif
        net_cards_conf[i].device_num = cbox->currentData().toInt();
        cbox                         = findChild<QComboBox *>(QString("comboBoxNet%1").arg(i + 1));
        net_cards_conf[i].net_type   = cbox->currentData().toInt();
        int current_net_type         = net_cards_conf[i].net_type;
        cbox                         = findChild<QComboBox *>(QString("comboBoxIntf%1").arg(i + 1));
        auto *hostname_value         = findChild<QLineEdit *>(QString("hostnameSwitch%1").arg(i + 1));
        auto *promisc_value          = findChild<QCheckBox *>(QString("boxPromisc%1").arg(i + 1));
        auto *secret_value           = findChild<QLineEdit *>(QString("secretSwitch%1").arg(i + 1));
        memset(net_cards_conf[i].host_dev_name, '\0', sizeof(net_cards_conf[i].host_dev_name));
        memset(net_cards_conf[i].vmnet_guest_ip, '\0', sizeof(net_cards_conf[i].vmnet_guest_ip));
        if (current_net_type == NET_TYPE_PCAP)
            strncpy(net_cards_conf[i].host_dev_name, network_devs[cbox->currentData().toInt()].device, sizeof(net_cards_conf[i].host_dev_name) - 1);
#ifdef __APPLE__
        else if (vmnet_type_uses_interface(current_net_type))
            strncpy(net_cards_conf[i].host_dev_name, network_devs[cbox->currentData().toInt()].device, sizeof(net_cards_conf[i].host_dev_name) - 1);
        else if (is_vmnet_type(current_net_type))
            strncpy(net_cards_conf[i].host_dev_name, "none", sizeof(net_cards_conf[i].host_dev_name) - 1);

        if (current_net_type == NET_TYPE_VMNET_NAT)
            strncpy(net_cards_conf[i].vmnet_guest_ip,
                    bridge_line->text().toUtf8().constData(),
                    sizeof(net_cards_conf[i].vmnet_guest_ip) - 1);
#endif
#ifdef HAS_VDE
        else if (net_cards_conf[i].net_type == NET_TYPE_VDE)
            strncpy(net_cards_conf[i].host_dev_name, socket_line->text().toUtf8().constData(), sizeof(net_cards_conf[i].host_dev_name) - 1);
#endif
#if defined(__unix__) || defined(__APPLE__)
        else if (net_cards_conf[i].net_type == NET_TYPE_TAP)
            strncpy(net_cards_conf[i].host_dev_name, bridge_line->text().toUtf8().constData(), sizeof(net_cards_conf[i].host_dev_name) - 1);
#endif
        else if (net_cards_conf[i].net_type == NET_TYPE_NRSWITCH) {
            memset(net_cards_conf[i].nrs_hostname, '\0', sizeof(net_cards_conf[i].nrs_hostname));
            strncpy(net_cards_conf[i].nrs_hostname, hostname_value->text().toUtf8().constData(), sizeof(net_cards_conf[i].nrs_hostname) - 1);
            memset(net_cards_conf[i].secret, '\0', sizeof(net_cards_conf[i].secret));
            strncpy(net_cards_conf[i].secret, secret_value->text().toUtf8().constData(), sizeof(net_cards_conf[i].secret) - 1);
        } else if (net_cards_conf[i].net_type == NET_TYPE_NLSWITCH) {
            net_cards_conf[i].promisc_mode = promisc_value->isChecked();
            memset(net_cards_conf[i].secret, '\0', sizeof(net_cards_conf[i].secret));
            strncpy(net_cards_conf[i].secret, secret_value->text().toUtf8().constData(), sizeof(net_cards_conf[i].secret) - 1);
        }

        if (net_cards_conf[i].host_dev_name[0] == 0x00)
            strncpy(net_cards_conf[i].host_dev_name, "none", 5);

        net_cards_conf[i].host_dev_name[sizeof(net_cards_conf[i].host_dev_name) - 1] = 0x00;
    }
}

void
SettingsNetwork::onCurrentMachineChanged(int machineId)
{
    this->machineId = machineId;

    int c           = 0;
    int selectedRow = 0;

    // Network Card
    QComboBox          *cbox_[NET_CARD_MAX]        = { 0 };
    QAbstractItemModel *models[NET_CARD_MAX]       = { 0 };
    int                 removeRows_[NET_CARD_MAX]  = { 0 };
    int                 selectedRows[NET_CARD_MAX] = { 0 };
    int                 m_has_net                  = machine_has_flags(machineId, MACHINE_NIC);

    for (uint8_t i = 0; i < NET_CARD_MAX; ++i) {
        sc[i]->removeRows();
        scDevice[i]->removeRows();
        cbox_[i]       = findChild<QComboBox *>(QString("comboBoxNIC%1").arg(i + 1));
        models[i]      = cbox_[i]->model();
        removeRows_[i] = models[i]->rowCount();
    }

    c = 0;
    while (true) {
        QString name = DeviceConfig::DeviceName(network_card_getdevice(c),
                                                network_card_get_internal_name(c), 1);

        if (name.isEmpty())
            break;

        if (network_card_available(c)) {
            if (device_is_valid(network_card_getdevice(c), machineId)) {
                for (uint8_t i = 0; i < NET_CARD_MAX; ++i) {
                    if ((c != 1) || ((i == 0) && m_has_net)) {
                        if (i == 0 && c == 1 && m_has_net && machine_get_net_device(machineId)) {
                            name += QString(" (%1)").arg(DeviceConfig::DeviceName(machine_get_net_device(machineId), machine_get_net_device(machineId)->internal_name, 0));
                        }
                        int row = Models::AddEntry(models[i], name, c);
                        sc[i]->addDevice(network_card_getdevice(c), name);

                        if (c == net_cards_conf[i].device_num)
                            selectedRows[i] = row - removeRows_[i];
                    }
                }
            }
        }

        c++;
    }

    for (uint8_t i = 0; i < NET_CARD_MAX; ++i) {
        models[i]->removeRows(0, removeRows_[i]);
        cbox_[i]->setEnabled(models[i]->rowCount() > 1);
        cbox_[i]->setCurrentIndex(-1);
        cbox_[i]->setCurrentIndex(selectedRows[i]);

        auto cbox       = findChild<QComboBox *>(QString("comboBoxNet%1").arg(i + 1));
        auto model      = cbox->model();
        auto removeRows = model->rowCount();
        Models::AddEntry(model, tr("Null Driver"), NET_TYPE_NONE);
        Models::AddEntry(model, "SLiRP", NET_TYPE_SLIRP);

        if (network_ndev > 1)
            Models::AddEntry(model, "PCap", NET_TYPE_PCAP);

#ifdef __APPLE__
        if (network_devmap.has_vmnet) {
            Models::AddEntry(model, "vmnet Shared (NAT)", NET_TYPE_VMNET_NAT);
            Models::AddEntry(model, "vmnet Host-Only", NET_TYPE_VMNET_HOST);
            Models::AddEntry(model, "vmnet Bridged", NET_TYPE_VMNET_BRIDGE);
            Models::AddEntry(model, "vmnet Published IP", NET_TYPE_VMNET_PUB);
        }
#endif

#ifdef HAS_VDE
        if (network_devmap.has_vde)
            Models::AddEntry(model, "VDE", NET_TYPE_VDE);
#endif

#if defined(__unix__) || defined(__APPLE__)
        Models::AddEntry(model, "TAP", NET_TYPE_TAP);
#endif

        Models::AddEntry(model, tr("Local Switch"), NET_TYPE_NLSWITCH);
#ifdef ENABLE_NET_NRSWITCH
        Models::AddEntry(model, tr("Remote Switch"), NET_TYPE_NRSWITCH);
#endif /* ENABLE_NET_NRSWITCH */

        model->removeRows(0, removeRows);
        cbox->setCurrentIndex(cbox->findData(net_cards_conf[i].net_type));

        selectedRow = 0;

        if (network_ndev > 0) {
            QString currentPcapDevice = net_cards_conf[i].host_dev_name;
#ifdef __APPLE__
            if (is_vmnet_type(net_cards_conf[i].net_type) &&
                is_legacy_vmnet_host_device_name(net_cards_conf[i].host_dev_name))
                currentPcapDevice.clear();
#endif
            populateInterfaceCombo(this, i, net_cards_conf[i].net_type, currentPcapDevice);
        }

        if (net_cards_conf[i].net_type == NET_TYPE_VDE) {
#ifdef HAS_VDE
            QString currentVdeSocket = net_cards_conf[i].host_dev_name;
            auto    editline         = findChild<QLineEdit *>(QString("socketVDENIC%1").arg(i + 1));
            editline->setText(currentVdeSocket);
#else
            ;
#endif
#if defined(__unix__) || defined(__APPLE__)
        } else if (net_cards_conf[i].net_type == NET_TYPE_TAP) {
            QString currentTapDevice = net_cards_conf[i].host_dev_name;
            auto    editline         = findChild<QLineEdit *>(QString("bridgeTAPNIC%1").arg(i + 1));
            editline->setText(currentTapDevice);
#ifdef __APPLE__
        } else if (net_cards_conf[i].net_type == NET_TYPE_VMNET_NAT) {
            QString currentGuestIp = net_cards_conf[i].vmnet_guest_ip;
            auto    editline       = findChild<QLineEdit *>(QString("bridgeTAPNIC%1").arg(i + 1));
            editline->setText(currentGuestIp);
#endif
#endif
        } else if (net_cards_conf[i].net_type == NET_TYPE_NLSWITCH) {
            auto *promisc_value = findChild<QCheckBox *>(QString("boxPromisc%1").arg(i + 1));
            promisc_value->setCheckState(net_cards_conf[i].promisc_mode == 1 ? Qt::CheckState::Checked : Qt::CheckState::Unchecked);
            auto *secret_value = findChild<QLineEdit *>(QString("secretSwitch%1").arg(i + 1));
            secret_value->setText(net_cards_conf[i].secret);
        } else if (net_cards_conf[i].net_type == NET_TYPE_NRSWITCH) {
            auto *hostname_value = findChild<QLineEdit *>(QString("hostnameSwitch%1").arg(i + 1));
            hostname_value->setText(net_cards_conf[i].nrs_hostname);
            auto *secret_value = findChild<QLineEdit *>(QString("secretSwitch%1").arg(i + 1));
            secret_value->setText(net_cards_conf[i].secret);
        }
    }
}

void
SettingsNetwork::on_comboIndexChanged(int index)
{
    if (index < 0)
        return;

    for (int i = 0; i < NET_CARD_MAX; ++i) {
        auto *net_type_cbox = findChild<QComboBox *>(QString("comboBoxNet%1").arg(i + 1));
        auto *intf_cbox     = findChild<QComboBox *>(QString("comboBoxIntf%1").arg(i + 1));

        QString currentDevice;
        if ((intf_cbox != nullptr) && intf_cbox->currentData().isValid()) {
            int dev_idx = intf_cbox->currentData().toInt();
            if ((dev_idx >= 0) && (dev_idx < network_ndev))
                currentDevice = network_devs[dev_idx].device;
        }

        populateInterfaceCombo(this, i, net_type_cbox->currentData().toInt(), currentDevice);
    }

    enableElements(ui);
}

void
SettingsNetwork::on_pushButtonConf1_clicked()
{
    int   netCard = ui->comboBoxNIC1->currentData().toInt();
    auto *device  = network_card_getdevice(netCard);
    if (netCard == NET_INTERNAL)
        device = machine_get_net_device(machineId);
    net_card_cfg_changed[0] = DeviceConfig::ConfigureDevice(device, 1);
}

void
SettingsNetwork::on_pushButtonConf2_clicked()
{
    int   netCard = ui->comboBoxNIC2->currentData().toInt();
    auto *device  = network_card_getdevice(netCard);
    net_card_cfg_changed[1] = DeviceConfig::ConfigureDevice(device, 2);
}

void
SettingsNetwork::on_pushButtonConf3_clicked()
{
    int   netCard = ui->comboBoxNIC3->currentData().toInt();
    auto *device  = network_card_getdevice(netCard);
    net_card_cfg_changed[2] = DeviceConfig::ConfigureDevice(device, 3);
}

void
SettingsNetwork::on_pushButtonConf4_clicked()
{
    int   netCard = ui->comboBoxNIC4->currentData().toInt();
    auto *device  = network_card_getdevice(netCard);
    net_card_cfg_changed[3] = DeviceConfig::ConfigureDevice(device, 4);
}
