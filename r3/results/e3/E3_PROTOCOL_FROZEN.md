# E3执行冻结，2026-10-29

按E3_DESIGN_FOR_FREEZE.md执行现有32769行比赛数据，原始数据hash固定，approved=30872。主单位七字段role profile；manager bucket仅独立敏感性。两个arm分开，部门与global对同一序列做嵌套配对。无时间字段，不声称时间顺序。

主分析k=1..10固定cohort：A纳入至少10不同approved resources的部门；B纳入至少10不同resources的(部门,profile)。每单位100次无放回排列（不同排列可相同），numpy PCG64固定种子2026102903，先排序单位/资源以稳定输入。每单位等权macro平均；approved-row频率加权作为独立敏感性，不用B中不同profile数量混淆部门权重。Manager版本相同规则独立运行。

报告筛选前后部门/代理单位、行数覆盖及排除数。另做k-specific全部可用cohort敏感性，清楚标注其跨k群体改变，不能把它解释成同一人群收缩。主固定cohort中计算中位/IQR、均值、0/1/≥2比例，pool配对增量和首次singleton步数；k10未singleton右删失。A允许0且不称攻击成功；B构造保证至少1，singleton只是唯一代理，不是重识别。

独立校验小人工集合手算、集合嵌套、逐k不增、B非空、配对pool不减，以及固定输入再跑一致。不产生身份映射公开文件；正式图表只汇总。保留原始分析日志和脚本hash；未许可不要上传数据/公开artifact。

本次不获取UCI大型payload；保留其为单独后续选项，不把两数据合并。此研究对象仍是共同来源假设下的语义代理，不是对Def4多次自适应定理的反例。
