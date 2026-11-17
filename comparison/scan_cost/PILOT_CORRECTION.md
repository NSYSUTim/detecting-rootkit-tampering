# 先導核對腳本更正

正式計時前的第一次十二狀態先導共 36 筆方法觀察及 12 筆無探針控制。本文正常與重排兩筆被外層腳本判不合格，原因是腳本要求 recovery_verified=true。既有正式輸出在無差異時明確給 recovery_status=no_difference_observed 及 recovery_verified=false，實際的 recovery_validation.verified 為 true，指紋、差集與量測品質都正確。其餘 34 筆合格。

更正只調整測試腳本：所有有效案例仍要求實際還原指紋核對通過，有差異時仍額外要求 recovery_verified=true。未修改偵測器、Go 執行檔、共同計時範圍、來源容量、順序或樣本數。另補存每種目錄大小最後的 manifest，供離線核對起訖輸入。第一次先導及原部署 ZIP 保留，修正後在新 confirmation 目錄重跑先導，通過後才執行正式三開機確認。先導不併入成本分母。
