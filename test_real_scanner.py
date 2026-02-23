#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار Cheek Real Scanner على أهداف آمنة للاختبار
Testing Cheek Real Scanner on Safe Targets
"""

import subprocess
import time
import json
from datetime import datetime

# أهداف آمنة للاختبار (مواقع مصممة لاختبار الثغرات)
SAFE_TARGETS = {
    'testphp.vulnweb.com': {
        'description': 'موقع اختبار من Acunetix - يحتوي على ثغرات متعمدة',
        'expected_findings': ['SQL Injection', 'XSS', 'Missing Security Headers']
    },
    'scanme.nmap.org': {
        'description': 'خادم اختبار Nmap الرسمي',
        'expected_findings': ['Open Ports', 'Service Detection']
    },
    'demo.testfire.net': {
        'description': 'تطبيق بنك وهمي للاختبار من IBM',
        'expected_findings': ['SQL Injection', 'XSS', 'CSRF']
    }
}

def print_banner():
    """طباعة شعار الاختبار"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║       Cheek Real Scanner - Test Suite                    ║
║        مجموعة اختبار الفاحص الحقيقي                     ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)

def test_target(target: str, info: dict):
    """اختبار هدف واحد"""
    print(f"\n{'='*60}")
    print(f"🎯 الهدف: {target}")
    print(f"📝 الوصف: {info['description']}")
    print(f"🔍 الثغرات المتوقعة: {', '.join(info['expected_findings'])}")
    print(f"{'='*60}\n")
    
    # تشغيل الفاحص
    start_time = time.time()
    
    try:
        result = subprocess.run(
            ['python3', 'cheek_real_scanner.py', target, '--verbose'],
            capture_output=True,
            text=True,
            timeout=120  # مهلة دقيقتين
        )
        
        execution_time = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"✓ الفحص اكتمل في {execution_time:.2f} ثانية")
        print(f"{'='*60}\n")
        
        # طباعة المخرجات
        print("المخرجات:")
        print(result.stdout)
        
        if result.stderr:
            print("\nالأخطاء:")
            print(result.stderr)
        
        return {
            'target': target,
            'success': result.returncode == 0,
            'execution_time': execution_time,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        
    except subprocess.TimeoutExpired:
        print(f"\n⏱️  تجاوز الفحص المهلة المحددة")
        return {
            'target': target,
            'success': False,
            'execution_time': 120,
            'error': 'Timeout'
        }
    except Exception as e:
        print(f"\n❌ خطأ في الفحص: {e}")
        return {
            'target': target,
            'success': False,
            'error': str(e)
        }

def run_all_tests():
    """تشغيل جميع الاختبارات"""
    print_banner()
    
    print("📊 سيتم اختبار الفاحص على الأهداف الآمنة التالية:")
    for target, info in SAFE_TARGETS.items():
        print(f"  • {target}")
    
    print(f"\n⚠️  تحذير: هذه الأهداف آمنة ومصممة للاختبار")
    print(f"⏱️  قد يستغرق الاختبار عدة دقائق...\n")
    
    input("اضغط Enter للبدء...")
    
    results = []
    
    for target, info in SAFE_TARGETS.items():
        result = test_target(target, info)
        results.append(result)
        time.sleep(2)  # انتظار قصير بين الاختبارات
    
    # ملخص النتائج
    print(f"\n{'='*60}")
    print("📊 ملخص نتائج الاختبار")
    print(f"{'='*60}\n")
    
    successful = sum(1 for r in results if r['success'])
    total = len(results)
    
    print(f"✓ اختبارات ناجحة: {successful}/{total}")
    print(f"❌ اختبارات فاشلة: {total - successful}/{total}")
    print(f"⏱️  إجمالي الوقت: {sum(r.get('execution_time', 0) for r in results):.2f}s")
    
    # حفظ النتائج
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"test_results_{timestamp}.json"
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 النتائج محفوظة في: {report_file}")

def quick_test():
    """اختبار سريع على هدف واحد"""
    print_banner()
    
    target = 'testphp.vulnweb.com'
    info = SAFE_TARGETS[target]
    
    print(f"🚀 اختبار سريع على: {target}\n")
    
    result = test_target(target, info)
    
    if result['success']:
        print(f"\n✅ الاختبار السريع نجح!")
    else:
        print(f"\n❌ الاختبار السريع فشل")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--quick':
        quick_test()
    else:
        run_all_tests()
