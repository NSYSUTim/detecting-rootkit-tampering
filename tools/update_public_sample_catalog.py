"""Update current reading entries; retain historical experiment reports."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def update(name,replacements):
    path=ROOT/name;text=path.read_text(encoding='utf-8')
    for old,new in replacements:
        assert text.count(old)==1,(name,old[:60],text.count(old))
        text=text.replace(old,new)
    path.write_text(text,encoding='utf-8',newline='\n')

update('README.md',[
 ('- [目前書面報告（revised38 乾淨版）](paper/cross_layer_directory_entry_consistency_revised38_zhTW.docx)',
  '- [目前書面報告（revised39）](paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx)／[PDF](paper/cross_layer_directory_entry_consistency_revised39_zhTW.pdf)\n'
  '- [面試研究摘要](paper/interview_research_summary_public_sample_zhTW.docx)／[PDF](paper/interview_research_summary_public_sample_zhTW.pdf)\n'
  '- [原版 CARAXES 三開機實測與未檢出邊界](docs/ORIGINAL_CARAXES_20261102_zh-TW.md)'),
 ('revised38 收錄三開機、相同輸入與準備完成後計時的成本比較，依實驗目的統一用詞，並修正方法解釋及下一步範圍。',
  'revised39 另納入固定原版 CARAXES 的兩配置、兩種掛接順序與三個新開機。正常對照 60 次一致，getdents64 模式 120 次警報並正確還原；filldir 模式 120 次造成清單截斷但兩端一致而未警報。兩端一致不能保證沒有隱藏。'),
 ('## 適用範圍與限制\n','## 適用範圍與限制\n\n- 原版 CARAXES 已另行實測。getdents64 模式每次缺少三筆並警報；filldir 模式回傳 false，正常 70 筆的目錄只交付 2 筆，核心摘要也只接受相同 2 筆，120 次均未警報。同場 zygarde 轉接版對 filldir 的 15 次皆有目標警報及檢查檔提示，不代表完整還原全部外部缺失。[規約、原始資料及重算](comparison/public_rootkit/README.md)\n')])
update('paper/README.md',[
 ('| 目前書面 | [revised38 乾淨版](cross_layer_directory_entry_consistency_revised38_zhTW.docx) | 以 revised37 為底，核對既有討論、程式與文獻，修正方法動機、下一步及結論，實驗表格與數據不變 |',
  '| 目前書面 | [revised39](cross_layer_directory_entry_consistency_revised39_zhTW.docx)／[PDF](cross_layer_directory_entry_consistency_revised39_zhTW.pdf) | 原版 CARAXES 的三開機結果，包含 getdents64 成功檢出與 filldir 截斷未警報 |\n'
  '| 面試摘要 | [Word](interview_research_summary_public_sample_zhTW.docx)／[PDF](interview_research_summary_public_sample_zhTW.pdf) | 依作者提供的摘要更新，成功與未檢出結果並列 |\n'
  '| 歷史書面 | [revised38 乾淨版](cross_layer_directory_entry_consistency_revised38_zhTW.docx) | 核對既有討論、程式與文獻，修正方法動機、下一步及結論 |'),
 ('現行入口沒有重跑原 1,296 批矩陣，沒有新增公開 rootkit；','現行入口沒有重跑原 1,296 批矩陣。原版 CARAXES 現已另組實測，正常 60 次一致、getdents64 模式 120 次警報並還原、filldir 模式 120 次截斷未警報，見 6.10 節及[結果與重算](../docs/ORIGINAL_CARAXES_20261102_zh-TW.md)。先前共同受控功能測試的')])
update('THIRD_PARTY_NOTICES.md',[
 ('本儲存庫未複製下列第三方專案的完整原始碼或執行檔。',
  '原版 CARAXES 的固定官方來源、GPL-3.0 LICENSE 及實際建置產物另收錄於 comparison/public_rootkit/public_sample_20261102.tar.gz，供核對來源。其餘下列第三方專案未整包收錄。'),
 ('未收錄完整 upstream；filldir 控制參照其掛接模式縮減實作，位於 `attack_variants/d7_controls_r2/`；getdents 控制與等量替換由本研究自行撰寫',
  '已另測官方原版 getdents64 與作者提供的 filldir 配置，封存含來源、LICENSE、配置差異及建置產物。舊受控 filldir 位於 `attack_variants/d7_controls_r2/`，命中時回傳 true，與原版 false 不同；getdents 控制與等量替換為自行實作')])
for name in ('docs/METHOD_AND_NEXT_STEPS_zh-TW.md','docs/METHOD_CLOSURE_20261102_zh-TW.md'):
    path=ROOT/name;text=path.read_text(encoding='utf-8')
    text=text.replace('revised38','revised39')
    split=text.index('\n')+1
    text=text[:split]+'\n原版 CARAXES 已完成另一組三開機實測：getdents64 模式 120 次警報並還原，正常 60 次一致，filldir 模式 120 次實際清單截斷但未警報。這組分母不與先前實驗合併，兩端一致不代表沒有隱藏。詳見[原始資料、原因與比較](ORIGINAL_CARAXES_20261102_zh-TW.md)。\n'+text[split:]
    path.write_text(text,encoding='utf-8',newline='\n')
for name in ('ARTIFACT_SCOPE.md','docs/RELATED_WORK_COMPARISON_zh-TW.md'):
    path=ROOT/name;text=path.read_text(encoding='utf-8');split=text.index('\n')+1
    prefix='../' if name.startswith('docs/') else ''
    text=text[:split]+f'\n本次另收錄固定原版 CARAXES 的三開機實驗、官方來源與 GPL-3.0 授權。getdents64 模式 120 次警報並還原，filldir 模式 120 次截斷未警報；同場 zygarde 對兩模式各 15 次有目標警報，filldir 同時有檢查檔品質提示。完整結果與證據見[實驗報告]({prefix}docs/ORIGINAL_CARAXES_20261102_zh-TW.md)。以前的受控比較不外推為兩者對此模式有相同涵蓋。\n'+text[split:]
    if name.startswith('docs/'):text=text.replace('(../docs/ORIGINAL_CARAXES_', '(ORIGINAL_CARAXES_')
    path.write_text(text,encoding='utf-8',newline='\n')
print('Updated seven current catalogs, with historical raw evidence unchanged.')
