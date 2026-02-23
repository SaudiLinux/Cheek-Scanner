#!/bin/bash
# تثبيت Cheek Real Scanner

set -e

# الألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          Cheek Real Scanner Installation                 ║${NC}"
echo -e "${BLUE}║              تثبيت فاحص Cheek الحقيقي                    ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# التحقق من Python
echo -e "${YELLOW}[1/5] التحقق من Python...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo -e "${GREEN}✓ Python3 موجود: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}✗ Python3 غير مثبت${NC}"
    echo -e "${YELLOW}يرجى تثبيت Python 3.7+ أولاً${NC}"
    exit 1
fi

# التحقق من pip
echo -e "${YELLOW}[2/5] التحقق من pip...${NC}"
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓ pip3 موجود${NC}"
else
    echo -e "${RED}✗ pip3 غير مثبت${NC}"
    echo -e "${YELLOW}يرجى تثبيت pip3 أولاً${NC}"
    exit 1
fi

# تثبيت المتطلبات
echo -e "${YELLOW}[3/5] تثبيت المتطلبات...${NC}"
pip3 install -r requirements_real.txt --quiet
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ تم تثبيت المتطلبات بنجاح${NC}"
else
    echo -e "${RED}✗ فشل تثبيت المتطلبات${NC}"
    exit 1
fi

# التحقق من nmap (اختياري)
echo -e "${YELLOW}[4/5] التحقق من nmap...${NC}"
if command -v nmap &> /dev/null; then
    echo -e "${GREEN}✓ nmap موجود${NC}"
else
    echo -e "${YELLOW}⚠  nmap غير مثبت (اختياري)${NC}"
    echo -e "${YELLOW}للحصول على أفضل النتائج، قم بتثبيت nmap:${NC}"
    echo -e "${YELLOW}  Ubuntu/Debian: sudo apt-get install nmap${NC}"
    echo -e "${YELLOW}  CentOS/RHEL: sudo yum install nmap${NC}"
    echo -e "${YELLOW}  macOS: brew install nmap${NC}"
fi

# جعل السكريبت قابل للتنفيذ
echo -e "${YELLOW}[5/5] إعداد الأذونات...${NC}"
chmod +x cheek_real_scanner.py
echo -e "${GREEN}✓ تم إعداد الأذونات${NC}"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Installation Completed Successfully!          ║${NC}"
echo -e "${GREEN}║               تم التثبيت بنجاح!                          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}الاستخدام:${NC}"
echo -e "${BLUE}  python3 cheek_real_scanner.py example.com${NC}"
echo -e "${BLUE}  python3 cheek_real_scanner.py example.com --threads 20${NC}"
echo -e "${BLUE}  python3 cheek_real_scanner.py example.com --verbose${NC}"
echo ""
echo -e "${YELLOW}للمساعدة:${NC}"
echo -e "${BLUE}  python3 cheek_real_scanner.py --help${NC}"
echo ""
