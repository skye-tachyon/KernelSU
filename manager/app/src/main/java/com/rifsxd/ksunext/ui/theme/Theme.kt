package com.rifsxd.ksunext.ui.theme

import android.content.Context
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import com.dergoogler.mmrl.ui.component.StatusBarStyle

private val DarkColorScheme = darkColorScheme(
    primary = PRIMARY,
    secondary = PRIMARY_DARK,
    tertiary = SECONDARY_DARK
)

private val LightColorScheme = lightColorScheme(
    primary = PRIMARY,
    secondary = PRIMARY_LIGHT,
    tertiary = SECONDARY_LIGHT
)

fun Color.blend(other: Color, ratio: Float): Color {
    val inverse = 1f - ratio
    return Color(
        red = red * inverse + other.red * ratio,
        green = green * inverse + other.green * ratio,
        blue = blue * inverse + other.blue * ratio,
        alpha = alpha
    )
}

/**
 * AMOLED colors are handled through the context
 */
fun Context.getColorScheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
): ColorScheme {
    // Read AMOLED mode preference
    val prefs = getSharedPreferences("settings", Context.MODE_PRIVATE)
    val amoledMode = prefs.getBoolean("enable_amoled", false)

    // Dynamic color is available on Android 12+
    val dynamicColor = true

    return when {
        amoledMode && darkTheme && dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val dynamicScheme = dynamicDarkColorScheme(this)
            dynamicScheme.copy(
                background = AMOLED_BLACK,
                surface = AMOLED_BLACK,
                surfaceVariant = dynamicScheme.surfaceVariant.blend(AMOLED_BLACK, 0.6f),
                surfaceContainer = dynamicScheme.surfaceContainer.blend(AMOLED_BLACK, 0.6f),
                surfaceContainerLow = dynamicScheme.surfaceContainerLow.blend(AMOLED_BLACK, 0.6f),
                surfaceContainerLowest = dynamicScheme.surfaceContainerLowest.blend(
                    AMOLED_BLACK,
                    0.6f
                ),
                surfaceContainerHigh = dynamicScheme.surfaceContainerHigh.blend(AMOLED_BLACK, 0.6f),
                surfaceContainerHighest = dynamicScheme.surfaceContainerHighest.blend(
                    AMOLED_BLACK,
                    0.6f
                ),
            )
        }

        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(this) else dynamicLightColorScheme(this)
        }

        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }
}

@Composable
fun KernelSUTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colorScheme = context.getColorScheme(darkTheme)

    StatusBarStyle(
        darkMode = darkTheme
    )

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}

internal fun isSystemInDarkTheme(): Boolean {
    val uiMode = Resources.getSystem().configuration.uiMode
    return (uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
}