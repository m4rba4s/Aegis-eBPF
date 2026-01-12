#!/bin/bash
# Использование: ./setup_isolation.sh /путь/к/Fedora-Workstation.iso

ISO_PATH="$1"

if [ -z "$ISO_PATH" ]; then
    echo "❌ Ошибка: Укажи путь к ISO образу."
    echo "Пример: $0 ~/Downloads/Fedora-Workstation-Live-x86_64-41-1.4.iso"
    exit 1
fi

if [ ! -f "$ISO_PATH" ]; then
    echo "❌ Ошибка: Файл $ISO_PATH не найден."
    exit 1
fi

echo "🚀 Настраиваю изолированную среду..."
echo "⚙️  CPU: Ryzen 9 (Host Passthrough) | RAM: 16GB | Disk: 64GB"

# Убедимся, что пул дефолтный активен
sudo virsh pool-define-as --name default --type dir --target /var/lib/libvirt/images 2>/dev/null
sudo virsh pool-start default 2>/dev/null
sudo virsh pool-autostart default 2>/dev/null

# Запуск установки
# --security type=none отключает лишние проверки SELinux для образа, если он в home директории
# --cpu host-passthrough критически важен для производительности и скрытия эмуляции
virt-install \
  --connect qemu:///system \
  --name "work-env-isolated" \
  --memory 16384 \
  --vcpus 8 \
  --cpu host-passthrough,cache.mode=passthrough \
  --disk size=64,pool=default,bus=virtio,format=qcow2,cache=none \
  --os-variant fedora41 \
  --network network=default,model=virtio \
  --graphics spice,listen=none \
  --video virtio \
  --channel spicevmc \
  --cdrom "$ISO_PATH" \
  --wait 0

echo "✅ Виртуальная машина создана и запускается."
echo "🖥  Открой 'Virtual Machine Manager' (virt-manager) чтобы завершить установку."
