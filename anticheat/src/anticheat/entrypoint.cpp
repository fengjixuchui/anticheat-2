#include "Core/Core.hpp"
#include "common.hpp"

int main()
{
    g_Instance = new anticheat(
        anticheat::Config{ 
            true,
            true,
            true,
            true,
            true
        }
    );

    g_Instance->CallbackOnceInit([] {
        printf("Anticheat has been initialized, your app is now protected.\n");
    });

    g_Instance->SetDetectionCallbacks(
        anticheat::DetectionCb{
            []{
                printf("A protected thread has been closed! \n");
            },
            []
            {
                printf("Detected thread in a non-registered module\n");
            },
            [](PWSTR path)
            {
				printf("ldrloaddll called with path %S\n", path);
                return false; 
                /*
                * return true if you want to block the dll from being loaded, and false to let it load.
                * You'll be able to make a white or blacklist of dlls.
                */
            },
            []
            {
                printf("Detected an exception in a non-registered module\n");
            }
        }
    );
    
    auto status = g_Instance->Init();
    if (!AC_SUCCESS(status))
    {
        printf("An error occured while trying to initialize the anticheat, code: %i\n", status);
        return 0;
    }

    getchar();
    return 0;
}