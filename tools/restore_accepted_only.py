"""Restore the prior accepted-only entry and catalogs without deleting evidence."""
import argparse,hashlib,json,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE='921319d5f0612227a14a8cad91065dfc18730092'
FILES=('scan_directory.py','README.md','ARTIFACT_SCOPE.md','THIRD_PARTY_NOTICES.md',
       'docs/METHOD_AND_NEXT_STEPS_zh-TW.md','docs/METHOD_CLOSURE_20261102_zh-TW.md',
       'docs/RELATED_WORK_COMPARISON_zh-TW.md','paper/README.md')
def main():
    p=argparse.ArgumentParser();p.add_argument('--git',required=True);a=p.parse_args()
    hashes={}
    for name in FILES:
        data=subprocess.check_output([a.git,'show',BASE+':'+name],cwd=ROOT)
        (ROOT/name).write_bytes(data);hashes[name]=hashlib.sha256(data).hexdigest()
    notice=('目前已撤回「最後一次回傳 false 就警報」的試驗規則，恢復加入該規則之前的已接受項目比對。'
      '目前書面為 revised39，原版 CARAXES 的 getdents64 模式可檢出，filldir 拒絕與提前截斷仍屬已確認的涵蓋限制。'
      'revised40 與終止拒絕實驗僅留作歷史，不當作現行成果。')
    for name in FILES[1:]:
        path=ROOT/name;text=path.read_text(encoding='utf-8');at=text.index('\n')+1
        link='ROLLBACK_ACCEPTED_ONLY_20261103_zh-TW.md' if name.startswith('docs/') else (
            '../docs/ROLLBACK_ACCEPTED_ONLY_20261103_zh-TW.md' if name.startswith('paper/') else 'docs/ROLLBACK_ACCEPTED_ONLY_20261103_zh-TW.md')
        text=text[:at]+'\n'+notice+' [撤回原因與核對]('+link+')。\n'+text[at:]
        if name=='README.md':text=text.replace('docs/PUBLICATION_VERIFICATION_CARAXES_20261102.json','docs/PUBLICATION_VERIFICATION_ROLLBACK_20261103.json')
        if name=='paper/README.md':
            text=text.replace('|---|---|---|','|---|---|---|\n| 撤回試驗版 | [revised40](cross_layer_directory_entry_consistency_revised40_zhTW.docx) | 終止拒絕規則有正常刪除警報，保留歷史，現行書面與入口已回復前版 |')
        path.write_text(text,encoding='utf-8',newline='\n')
    for name in ('terminal_rejection/README.md','docs/TERMINAL_REJECTION_20261103_zh-TW.md'):
        path=ROOT/name;text=path.read_text(encoding='utf-8');at=text.index('\n')+1
        note=('**已撤回，僅供歷史重現。** 現行 scan_directory.py 已恢復接受項目比對，預設不使用這條規則。'
              '本頁記錄的是撤回前的試驗與正常刪除警報，不是現行功能。')
        text=text[:at]+'\n'+note+'\n'+text[at:]
        path.write_text(text,encoding='utf-8',newline='\n')
    output=ROOT/'_docx_work/terminal_rollback';output.mkdir(parents=True,exist_ok=True)
    (output/'restored_baseline.json').write_text(json.dumps({'baseline':BASE,'restored_before_status_notes':hashes},indent=2),encoding='utf-8')
    print('Restored accepted-only entry; historical experiment sources and raw data retained.')
if __name__=='__main__':main()
