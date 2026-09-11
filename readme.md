# Операционные системы

Учебно-методические материалы по дисциплине **«Операционные системы»**: лекции, практические и контрольные работы, рабочие программы и фонды оценочных средств.

> Этот файл формируется автоматически из текущей структуры репозитория. Не редактируйте его вручную: изменения будут заменены при следующем запуске генератора.

## Направления подготовки

| Каталог | Направление |
|---|---|
| [ИВТ](./%D0%98%D0%92%D0%A2) | 09.03.01 «Информатика и вычислительная техника» |
| [КБ](./%D0%9A%D0%91) | 10.05.01 «Компьютерная безопасность» |
| [ПИ](./%D0%9F%D0%98) | 09.03.04 «Программная инженерия» |

## Состав репозитория

- каталогов: **30**;
- файлов: **106**;
- учебных документов: **22**;
- изображений и схем: **82**.

## Структура каталогов

```text
Operating_System/
├── .github/
│   └── workflows/
│       └── update-readme.yml
├── scripts/
│   └── generate_readme.py
├── ИВТ/
│   ├── КР/
│   │   └── readme.md
│   ├── Лекции/
│   │   └── readme.md
│   ├── Практики/
│   │   └── readme.md
│   ├── РПД и ФОС/
│   │   └── readme.md
│   └── readme.md
├── КБ/
│   ├── КР/
│   │   └── readme.md
│   ├── Лекции/
│   │   ├── Lection 1/
│   │   │   ├── figures/
│   │   │   │   ├── figure_01_os_roles.png
│   │   │   │   ├── figure_02_layered_model.png
│   │   │   │   ├── figure_03_privilege_boundary.png
│   │   │   │   ├── figure_04_os_evolution.png
│   │   │   │   ├── figure_05_classification.png
│   │   │   │   ├── figure_06_security_properties.png
│   │   │   │   ├── figure_07_policy_mechanism.png
│   │   │   │   ├── figure_08_tcb.png
│   │   │   │   ├── figure_09_controlled_access.png
│   │   │   │   ├── figure_10_attack_surface.png
│   │   │   │   ├── figure_11_risk_chain.png
│   │   │   │   ├── figure_12_analysis_chain.png
│   │   │   │   ├── figure_13_baseline.png
│   │   │   │   ├── figure_14_security_cycle.png
│   │   │   │   ├── figure_15_training_stand.png
│   │   │   │   ├── figure_16_stand_model.png
│   │   │   │   └── figure_17_verification_modes.png
│   │   │   └── Конспект_лекции_1_ОС_как_объект_защиты.md
│   │   ├── lecture_2_os_architecture/
│   │   │   ├── figures/
│   │   │   │   ├── figure_01_kernel_role.png
│   │   │   │   ├── figure_02_privilege_boundary.png
│   │   │   │   ├── figure_03_mmu_memory_protection.png
│   │   │   │   ├── figure_04_kernel_entry_reasons.png
│   │   │   │   ├── figure_05_syscall_contract.png
│   │   │   │   ├── figure_06_api_abi.png
│   │   │   │   ├── figure_07_syscall_classes.png
│   │   │   │   ├── figure_08_descriptors.png
│   │   │   │   ├── figure_09_untrusted_user_data.png
│   │   │   │   ├── figure_10_toctou.png
│   │   │   │   ├── figure_11_monolithic_kernel.png
│   │   │   │   ├── figure_12_microkernel.png
│   │   │   │   ├── figure_13_architecture_comparison.png
│   │   │   │   ├── figure_14_interrupts_drivers.png
│   │   │   │   ├── figure_15_interrupt_handling.png
│   │   │   │   ├── figure_16_iommu.png
│   │   │   │   └── figure_17_open_read_path.png
│   │   │   └── Конспект_лекции_2_Архитектуры_ОС_и_системные_вызовы.md
│   │   ├── lecture_3_processes_threads_scheduling/
│   │   │   ├── figures/
│   │   │   │   ├── figure_01_program_process_thread.png
│   │   │   │   ├── figure_02_pcb.png
│   │   │   │   ├── figure_03_address_space.png
│   │   │   │   ├── figure_04_process_states.png
│   │   │   │   ├── figure_05_process_lifecycle.png
│   │   │   │   ├── figure_06_thread_model.png
│   │   │   │   ├── figure_07_thread_mapping.png
│   │   │   │   ├── figure_08_race_condition.png
│   │   │   │   ├── figure_09_process_thread_boundary.png
│   │   │   │   ├── figure_10_context_switch.png
│   │   │   │   ├── figure_11_round_robin.png
│   │   │   │   ├── figure_12_priority_inversion.png
│   │   │   │   ├── figure_13_multicore_scheduling.png
│   │   │   │   ├── figure_14_realtime_scheduling.png
│   │   │   │   ├── figure_15_security_context.png
│   │   │   │   ├── figure_16_isolation_layers.png
│   │   │   │   ├── figure_17_secure_service.png
│   │   │   │   └── figure_18_isolation_tests.png
│   │   │   └── Конспект_лекции_3_Процессы_потоки_и_планирование.md
│   │   └── OS-lecture-notes.md
│   ├── Практики/
│   │   ├── lab01-os-isolated-stand/
│   │   │   ├── images/
│   │   │   │   ├── figure-01.png
│   │   │   │   ├── figure-02.png
│   │   │   │   ├── figure-03.png
│   │   │   │   ├── figure-04.png
│   │   │   │   ├── figure-05.png
│   │   │   │   ├── figure-06.png
│   │   │   │   ├── figure-07.png
│   │   │   │   ├── figure-08.png
│   │   │   │   ├── figure-09.png
│   │   │   │   └── figure-10.png
│   │   │   └── Lab1.md
│   │   ├── lab02-os-inventory-baseline/
│   │   │   ├── images/
│   │   │   │   ├── figure-01.png
│   │   │   │   ├── figure-02.png
│   │   │   │   ├── figure-03.png
│   │   │   │   ├── figure-04.png
│   │   │   │   ├── figure-05.png
│   │   │   │   ├── figure-06.png
│   │   │   │   ├── figure-07.png
│   │   │   │   ├── figure-08.png
│   │   │   │   ├── figure-09.png
│   │   │   │   └── figure-10.png
│   │   │   └── Lab2.md
│   │   ├── lab03-processes-syscalls-fd/
│   │   │   ├── images/
│   │   │   │   ├── figure-01.png
│   │   │   │   ├── figure-02.png
│   │   │   │   ├── figure-03.png
│   │   │   │   ├── figure-04.png
│   │   │   │   ├── figure-05.png
│   │   │   │   ├── figure-06.png
│   │   │   │   ├── figure-07.png
│   │   │   │   ├── figure-08.png
│   │   │   │   ├── figure-09.png
│   │   │   │   └── figure-10.png
│   │   │   └── Lab03.md
│   │   └── readme.md
│   ├── РПД и ФОС/
│   │   ├── readme.md
│   │   └── RPD_Operatsionnye_sistemy_10.05.01.md
│   └── readme.md
└── ПИ/
    ├── КР/
    │   └── readme.md
    ├── Лекции/
    │   └── readme.md
    ├── Практики/
    │   └── readme.md
    ├── РПД и ФОС/
    │   └── readme.md
    └── readme.md
```

## Содержание каталогов

### Корень репозитория

**Подкаталоги**

- [.github](./.github) — Материалы раздела; `.github/`
- [scripts](./scripts) — Материалы раздела; `scripts/`
- [ИВТ](./%D0%98%D0%92%D0%A2) — 09.03.01 «Информатика и вычислительная техника»; `ИВТ/`
- [КБ](./%D0%9A%D0%91) — 10.05.01 «Компьютерная безопасность»; `КБ/`
- [ПИ](./%D0%9F%D0%98) — 09.03.04 «Программная инженерия»; `ПИ/`

### .github

**Подкаталоги**

- [workflows](./.github/workflows) — Материалы раздела; `.github/workflows/`

### scripts

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [generate_readme.py](./scripts/generate_readme.py) | generate readme | Python |

### ИВТ

**Подкаталоги**

- [КР](./%D0%98%D0%92%D0%A2/%D0%9A%D0%A0) — Материалы раздела; `ИВТ/КР/`
- [Лекции](./%D0%98%D0%92%D0%A2/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8) — Материалы раздела; `ИВТ/Лекции/`
- [Практики](./%D0%98%D0%92%D0%A2/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8) — Материалы раздела; `ИВТ/Практики/`
- [РПД и ФОС](./%D0%98%D0%92%D0%A2/%D0%A0%D0%9F%D0%94%20%D0%B8%20%D0%A4%D0%9E%D0%A1) — Материалы раздела; `ИВТ/РПД и ФОС/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%98%D0%92%D0%A2/readme.md) | readme | Markdown |

### КБ

**Подкаталоги**

- [КР](./%D0%9A%D0%91/%D0%9A%D0%A0) — Материалы раздела; `КБ/КР/`
- [Лекции](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8) — Материалы раздела; `КБ/Лекции/`
- [Практики](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8) — Материалы раздела; `КБ/Практики/`
- [РПД и ФОС](./%D0%9A%D0%91/%D0%A0%D0%9F%D0%94%20%D0%B8%20%D0%A4%D0%9E%D0%A1) — Материалы раздела; `КБ/РПД и ФОС/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9A%D0%91/readme.md) | readme | Markdown |

### ПИ

**Подкаталоги**

- [КР](./%D0%9F%D0%98/%D0%9A%D0%A0) — Материалы раздела; `ПИ/КР/`
- [Лекции](./%D0%9F%D0%98/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8) — Материалы раздела; `ПИ/Лекции/`
- [Практики](./%D0%9F%D0%98/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8) — Материалы раздела; `ПИ/Практики/`
- [РПД и ФОС](./%D0%9F%D0%98/%D0%A0%D0%9F%D0%94%20%D0%B8%20%D0%A4%D0%9E%D0%A1) — Материалы раздела; `ПИ/РПД и ФОС/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9F%D0%98/readme.md) | readme | Markdown |

### .github/workflows

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [update-readme.yml](./.github/workflows/update-readme.yml) | update readme | YAML |

### ИВТ/КР

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%98%D0%92%D0%A2/%D0%9A%D0%A0/readme.md) | readme | Markdown |

### ИВТ/Лекции

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%98%D0%92%D0%A2/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/readme.md) | readme | Markdown |

### ИВТ/Практики

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%98%D0%92%D0%A2/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/readme.md) | readme | Markdown |

### ИВТ/РПД и ФОС

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%98%D0%92%D0%A2/%D0%A0%D0%9F%D0%94%20%D0%B8%20%D0%A4%D0%9E%D0%A1/readme.md) | readme | Markdown |

### КБ/КР

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9A%D0%91/%D0%9A%D0%A0/readme.md) | Контрольные работы | Markdown |

### КБ/Лекции

**Подкаталоги**

- [Lection 1](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201) — Материалы раздела; `КБ/Лекции/Lection 1/`
- [lecture_2_os_architecture](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture) — Материалы раздела; `КБ/Лекции/lecture_2_os_architecture/`
- [lecture_3_processes_threads_scheduling](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling) — Материалы раздела; `КБ/Лекции/lecture_3_processes_threads_scheduling/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [OS-lecture-notes.md](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/OS-lecture-notes.md) | Операционные системы | Markdown |

### КБ/Практики

**Подкаталоги**

- [lab01-os-isolated-stand](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand) — Материалы раздела; `КБ/Практики/lab01-os-isolated-stand/`
- [lab02-os-inventory-baseline](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline) — Материалы раздела; `КБ/Практики/lab02-os-inventory-baseline/`
- [lab03-processes-syscalls-fd](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd) — Материалы раздела; `КБ/Практики/lab03-processes-syscalls-fd/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/readme.md) | readme | Markdown |

### КБ/РПД и ФОС

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9A%D0%91/%D0%A0%D0%9F%D0%94%20%D0%B8%20%D0%A4%D0%9E%D0%A1/readme.md) | readme | Markdown |
| [RPD_Operatsionnye_sistemy_10.05.01.md](./%D0%9A%D0%91/%D0%A0%D0%9F%D0%94%20%D0%B8%20%D0%A4%D0%9E%D0%A1/RPD_Operatsionnye_sistemy_10.05.01.md) | ПАСПОРТ РАБОЧЕЙ ПРОГРАММЫ | Markdown |

### ПИ/КР

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9F%D0%98/%D0%9A%D0%A0/readme.md) | readme | Markdown |

### ПИ/Лекции

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9F%D0%98/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/readme.md) | readme | Markdown |

### ПИ/Практики

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9F%D0%98/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/readme.md) | readme | Markdown |

### ПИ/РПД и ФОС

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [readme.md](./%D0%9F%D0%98/%D0%A0%D0%9F%D0%94%20%D0%B8%20%D0%A4%D0%9E%D0%A1/readme.md) | readme | Markdown |

### КБ/Лекции/Lection 1

**Подкаталоги**

- [figures](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures) — Материалы раздела; `КБ/Лекции/Lection 1/figures/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [Конспект_лекции_1_ОС_как_объект_защиты.md](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/%D0%9A%D0%BE%D0%BD%D1%81%D0%BF%D0%B5%D0%BA%D1%82_%D0%BB%D0%B5%D0%BA%D1%86%D0%B8%D0%B8_1_%D0%9E%D0%A1_%D0%BA%D0%B0%D0%BA_%D0%BE%D0%B1%D1%8A%D0%B5%D0%BA%D1%82_%D0%B7%D0%B0%D1%89%D0%B8%D1%82%D1%8B.md) | Операционная система как объект защиты | Markdown |

### КБ/Лекции/lecture_2_os_architecture

**Подкаталоги**

- [figures](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures) — Материалы раздела; `КБ/Лекции/lecture_2_os_architecture/figures/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [Конспект_лекции_2_Архитектуры_ОС_и_системные_вызовы.md](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/%D0%9A%D0%BE%D0%BD%D1%81%D0%BF%D0%B5%D0%BA%D1%82_%D0%BB%D0%B5%D0%BA%D1%86%D0%B8%D0%B8_2_%D0%90%D1%80%D1%85%D0%B8%D1%82%D0%B5%D0%BA%D1%82%D1%83%D1%80%D1%8B_%D0%9E%D0%A1_%D0%B8_%D1%81%D0%B8%D1%81%D1%82%D0%B5%D0%BC%D0%BD%D1%8B%D0%B5_%D0%B2%D1%8B%D0%B7%D0%BE%D0%B2%D1%8B.md) | Архитектуры ОС и системные вызовы | Markdown |

### КБ/Лекции/lecture_3_processes_threads_scheduling

**Подкаталоги**

- [figures](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures) — Материалы раздела; `КБ/Лекции/lecture_3_processes_threads_scheduling/figures/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [Конспект_лекции_3_Процессы_потоки_и_планирование.md](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/%D0%9A%D0%BE%D0%BD%D1%81%D0%BF%D0%B5%D0%BA%D1%82_%D0%BB%D0%B5%D0%BA%D1%86%D0%B8%D0%B8_3_%D0%9F%D1%80%D0%BE%D1%86%D0%B5%D1%81%D1%81%D1%8B_%D0%BF%D0%BE%D1%82%D0%BE%D0%BA%D0%B8_%D0%B8_%D0%BF%D0%BB%D0%B0%D0%BD%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5.md) | Процессы, потоки и планирование | Markdown |

### КБ/Практики/lab01-os-isolated-stand

**Подкаталоги**

- [images](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images) — Материалы раздела; `КБ/Практики/lab01-os-isolated-stand/images/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [Lab1.md](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/Lab1.md) | Практическая работа № 1. Изолированный виртуальный стенд и паспорт операционной системы | Markdown |

### КБ/Практики/lab02-os-inventory-baseline

**Подкаталоги**

- [images](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images) — Материалы раздела; `КБ/Практики/lab02-os-inventory-baseline/images/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [Lab2.md](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/Lab2.md) | Практическая работа № 2. Инвентаризация операционной системы и формирование baseline | Markdown |

### КБ/Практики/lab03-processes-syscalls-fd

**Подкаталоги**

- [images](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images) — Материалы раздела; `КБ/Практики/lab03-processes-syscalls-fd/images/`

**Файлы**

| Файл | Содержание | Формат |
|---|---|---|
| [Lab03.md](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/Lab03.md) | Практическая работа № 3. Процессы, системные вызовы и файловые дескрипторы | Markdown |

### КБ/Лекции/Lection 1/figures

<details>
<summary>Изображения: 17</summary>

| Файл | Содержание | Формат |
|---|---|---|
| [figure_01_os_roles.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_01_os_roles.png) | figure 01 os roles | PNG |
| [figure_02_layered_model.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_02_layered_model.png) | figure 02 layered model | PNG |
| [figure_03_privilege_boundary.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_03_privilege_boundary.png) | figure 03 privilege boundary | PNG |
| [figure_04_os_evolution.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_04_os_evolution.png) | figure 04 os evolution | PNG |
| [figure_05_classification.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_05_classification.png) | figure 05 classification | PNG |
| [figure_06_security_properties.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_06_security_properties.png) | figure 06 security properties | PNG |
| [figure_07_policy_mechanism.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_07_policy_mechanism.png) | figure 07 policy mechanism | PNG |
| [figure_08_tcb.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_08_tcb.png) | figure 08 tcb | PNG |
| [figure_09_controlled_access.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_09_controlled_access.png) | figure 09 controlled access | PNG |
| [figure_10_attack_surface.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_10_attack_surface.png) | figure 10 attack surface | PNG |
| [figure_11_risk_chain.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_11_risk_chain.png) | figure 11 risk chain | PNG |
| [figure_12_analysis_chain.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_12_analysis_chain.png) | figure 12 analysis chain | PNG |
| [figure_13_baseline.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_13_baseline.png) | figure 13 baseline | PNG |
| [figure_14_security_cycle.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_14_security_cycle.png) | figure 14 security cycle | PNG |
| [figure_15_training_stand.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_15_training_stand.png) | figure 15 training stand | PNG |
| [figure_16_stand_model.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_16_stand_model.png) | figure 16 stand model | PNG |
| [figure_17_verification_modes.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/Lection%201/figures/figure_17_verification_modes.png) | figure 17 verification modes | PNG |

</details>

### КБ/Лекции/lecture_2_os_architecture/figures

<details>
<summary>Изображения: 17</summary>

| Файл | Содержание | Формат |
|---|---|---|
| [figure_01_kernel_role.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_01_kernel_role.png) | figure 01 kernel role | PNG |
| [figure_02_privilege_boundary.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_02_privilege_boundary.png) | figure 02 privilege boundary | PNG |
| [figure_03_mmu_memory_protection.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_03_mmu_memory_protection.png) | figure 03 mmu memory protection | PNG |
| [figure_04_kernel_entry_reasons.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_04_kernel_entry_reasons.png) | figure 04 kernel entry reasons | PNG |
| [figure_05_syscall_contract.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_05_syscall_contract.png) | figure 05 syscall contract | PNG |
| [figure_06_api_abi.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_06_api_abi.png) | figure 06 api abi | PNG |
| [figure_07_syscall_classes.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_07_syscall_classes.png) | figure 07 syscall classes | PNG |
| [figure_08_descriptors.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_08_descriptors.png) | figure 08 descriptors | PNG |
| [figure_09_untrusted_user_data.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_09_untrusted_user_data.png) | figure 09 untrusted user data | PNG |
| [figure_10_toctou.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_10_toctou.png) | figure 10 toctou | PNG |
| [figure_11_monolithic_kernel.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_11_monolithic_kernel.png) | figure 11 monolithic kernel | PNG |
| [figure_12_microkernel.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_12_microkernel.png) | figure 12 microkernel | PNG |
| [figure_13_architecture_comparison.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_13_architecture_comparison.png) | figure 13 architecture comparison | PNG |
| [figure_14_interrupts_drivers.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_14_interrupts_drivers.png) | figure 14 interrupts drivers | PNG |
| [figure_15_interrupt_handling.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_15_interrupt_handling.png) | figure 15 interrupt handling | PNG |
| [figure_16_iommu.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_16_iommu.png) | figure 16 iommu | PNG |
| [figure_17_open_read_path.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_2_os_architecture/figures/figure_17_open_read_path.png) | figure 17 open read path | PNG |

</details>

### КБ/Лекции/lecture_3_processes_threads_scheduling/figures

<details>
<summary>Изображения: 18</summary>

| Файл | Содержание | Формат |
|---|---|---|
| [figure_01_program_process_thread.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_01_program_process_thread.png) | figure 01 program process thread | PNG |
| [figure_02_pcb.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_02_pcb.png) | figure 02 pcb | PNG |
| [figure_03_address_space.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_03_address_space.png) | figure 03 address space | PNG |
| [figure_04_process_states.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_04_process_states.png) | figure 04 process states | PNG |
| [figure_05_process_lifecycle.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_05_process_lifecycle.png) | figure 05 process lifecycle | PNG |
| [figure_06_thread_model.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_06_thread_model.png) | figure 06 thread model | PNG |
| [figure_07_thread_mapping.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_07_thread_mapping.png) | figure 07 thread mapping | PNG |
| [figure_08_race_condition.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_08_race_condition.png) | figure 08 race condition | PNG |
| [figure_09_process_thread_boundary.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_09_process_thread_boundary.png) | figure 09 process thread boundary | PNG |
| [figure_10_context_switch.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_10_context_switch.png) | figure 10 context switch | PNG |
| [figure_11_round_robin.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_11_round_robin.png) | figure 11 round robin | PNG |
| [figure_12_priority_inversion.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_12_priority_inversion.png) | figure 12 priority inversion | PNG |
| [figure_13_multicore_scheduling.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_13_multicore_scheduling.png) | figure 13 multicore scheduling | PNG |
| [figure_14_realtime_scheduling.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_14_realtime_scheduling.png) | figure 14 realtime scheduling | PNG |
| [figure_15_security_context.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_15_security_context.png) | figure 15 security context | PNG |
| [figure_16_isolation_layers.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_16_isolation_layers.png) | figure 16 isolation layers | PNG |
| [figure_17_secure_service.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_17_secure_service.png) | figure 17 secure service | PNG |
| [figure_18_isolation_tests.png](./%D0%9A%D0%91/%D0%9B%D0%B5%D0%BA%D1%86%D0%B8%D0%B8/lecture_3_processes_threads_scheduling/figures/figure_18_isolation_tests.png) | figure 18 isolation tests | PNG |

</details>

### КБ/Практики/lab01-os-isolated-stand/images

<details>
<summary>Изображения: 10</summary>

| Файл | Содержание | Формат |
|---|---|---|
| [figure-01.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-01.png) | figure 01 | PNG |
| [figure-02.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-02.png) | figure 02 | PNG |
| [figure-03.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-03.png) | figure 03 | PNG |
| [figure-04.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-04.png) | figure 04 | PNG |
| [figure-05.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-05.png) | figure 05 | PNG |
| [figure-06.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-06.png) | figure 06 | PNG |
| [figure-07.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-07.png) | figure 07 | PNG |
| [figure-08.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-08.png) | figure 08 | PNG |
| [figure-09.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-09.png) | figure 09 | PNG |
| [figure-10.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab01-os-isolated-stand/images/figure-10.png) | figure 10 | PNG |

</details>

### КБ/Практики/lab02-os-inventory-baseline/images

<details>
<summary>Изображения: 10</summary>

| Файл | Содержание | Формат |
|---|---|---|
| [figure-01.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-01.png) | figure 01 | PNG |
| [figure-02.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-02.png) | figure 02 | PNG |
| [figure-03.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-03.png) | figure 03 | PNG |
| [figure-04.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-04.png) | figure 04 | PNG |
| [figure-05.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-05.png) | figure 05 | PNG |
| [figure-06.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-06.png) | figure 06 | PNG |
| [figure-07.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-07.png) | figure 07 | PNG |
| [figure-08.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-08.png) | figure 08 | PNG |
| [figure-09.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-09.png) | figure 09 | PNG |
| [figure-10.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab02-os-inventory-baseline/images/figure-10.png) | figure 10 | PNG |

</details>

### КБ/Практики/lab03-processes-syscalls-fd/images

<details>
<summary>Изображения: 10</summary>

| Файл | Содержание | Формат |
|---|---|---|
| [figure-01.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-01.png) | figure 01 | PNG |
| [figure-02.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-02.png) | figure 02 | PNG |
| [figure-03.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-03.png) | figure 03 | PNG |
| [figure-04.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-04.png) | figure 04 | PNG |
| [figure-05.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-05.png) | figure 05 | PNG |
| [figure-06.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-06.png) | figure 06 | PNG |
| [figure-07.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-07.png) | figure 07 | PNG |
| [figure-08.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-08.png) | figure 08 | PNG |
| [figure-09.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-09.png) | figure 09 | PNG |
| [figure-10.png](./%D0%9A%D0%91/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D0%BA%D0%B8/lab03-processes-syscalls-fd/images/figure-10.png) | figure 10 | PNG |

</details>

## Как обновляется этот файл

После изменения содержимого ветки `main` GitHub Actions запускает `scripts/generate_readme.py`. Если структура или набор файлов изменились, workflow создаёт новый `readme.md` и фиксирует его отдельным коммитом.

Локальная генерация:

```bash
python scripts/generate_readme.py
```

Проверка актуальности без изменения файла:

```bash
python scripts/generate_readme.py --check
```

## Правила безопасной работы

> Все действия по настройке, диагностике и проверке безопасности выполняются только в разрешённой учебной среде. Воздействие на сторонние системы и сети запрещено.
