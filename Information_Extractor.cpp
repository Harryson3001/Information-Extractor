#include "PEinfo.h"
#include <stdio.h>

int wmain() {
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argc < 2) {
        system("cls");
        SetConsoleTitleW(L"Information Extractor");
        wprintf(L"\n  [i] Arraste um arquivo .exe sobre este programa\n\n");
        printf("  Pressione ENTER para fechar...");
        getchar();
        return 0;
    }

    if (!PEInfoExtractor::ExtractAndPrint(argv[1])) {
        printf("\n[!] Erro: Arquivo invalido ou nao e um executavel PE valido.\n\n");
        printf("Pressione ENTER para fechar...");
        getchar();
    }
    else {
        printf("Pressione ENTER para fechar...");
        getchar();
    }

    LocalFree(argv);
    return 0;
}