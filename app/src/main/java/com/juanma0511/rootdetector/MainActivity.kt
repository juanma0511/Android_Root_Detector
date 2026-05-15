package com.juanma0511.rootdetector

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.*
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.juanma0511.rootdetector.ui.*

data class NavItem(
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

val navItems = listOf(
    NavItem("Root Scan",   Icons.Filled.Security,  Icons.Outlined.Security),
    NavItem("HW Security", Icons.Filled.Hardware,  Icons.Outlined.Hardware),
    NavItem("Settings",    Icons.Filled.Settings,  Icons.Outlined.Settings)
)

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val prefs = getSharedPreferences("rootdetector_prefs", Context.MODE_PRIVATE)
            var themeMode by remember {
                mutableStateOf(
                    when (prefs.getString("theme_mode", "SYSTEM")) {
                        "LIGHT" -> ThemeMode.LIGHT
                        "DARK"  -> ThemeMode.DARK
                        else    -> ThemeMode.SYSTEM
                    }
                )
            }

            RootDetectorTheme(themeMode = themeMode) {
                MainShell(
                    viewModel     = viewModel,
                    themeMode     = themeMode,
                    onThemeChange = { mode ->
                        themeMode = mode
                        prefs.edit().putString("theme_mode", mode.name).apply()
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainShell(
    viewModel: MainViewModel,
    themeMode: ThemeMode,
    onThemeChange: (ThemeMode) -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }

    val titles = listOf("kknd Detector", "Hardware Security", "Settings")

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        titles[selectedTab],
                        style = MaterialTheme.typography.titleLarge
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(horizontal = 24.dp, vertical = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                PillNavigationBar(
                    selectedTab    = selectedTab,
                    onTabSelected  = { selectedTab = it }
                )
            }
        }
    ) { padding ->
        Box(modifier = Modifier
            .padding(padding)
            .fillMaxSize()) {
            AnimatedContent(
                targetState = selectedTab,
                transitionSpec = {
                    if (targetState > initialState) {
                        slideInHorizontally { it } + fadeIn() togetherWith
                            slideOutHorizontally { -it } + fadeOut()
                    } else {
                        slideInHorizontally { -it } + fadeIn() togetherWith
                            slideOutHorizontally { it } + fadeOut()
                    }
                },
                label = "tab_transition"
            ) { tab ->
                when (tab) {
                    0    -> RootDetectorScreen(viewModel)
                    1    -> HwSecurityScreen(viewModel)
                    else -> SettingsScreen(
                                currentTheme  = themeMode,
                                onThemeChange = onThemeChange
                            )
                }
            }
        }
    }
}

@Composable
fun PillNavigationBar(
    selectedTab: Int,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier  = modifier,
        shape     = RoundedCornerShape(50.dp),
        color     = MaterialTheme.colorScheme.surfaceVariant,
        tonalElevation = 3.dp,
        shadowElevation = 4.dp
    ) {
        Row(
            modifier = Modifier.padding(6.dp),
            verticalAlignment    = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            navItems.forEachIndexed { index, item ->
                PillNavItem(
                    item     = item,
                    selected = selectedTab == index,
                    onClick  = { onTabSelected(index) }
                )
            }
        }
    }
}

@Composable
fun PillNavItem(
    item: NavItem,
    selected: Boolean,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape   = RoundedCornerShape(50.dp),
        color   = if (selected) MaterialTheme.colorScheme.secondaryContainer
                  else          MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.animateContentSize(
            animationSpec = spring(
                dampingRatio = Spring.DampingRatioMediumBouncy,
                stiffness    = Spring.StiffnessMedium
            )
        )
    ) {
        Row(
            modifier = Modifier.padding(
                horizontal = if (selected) 20.dp else 14.dp,
                vertical   = 14.dp
            ),
            verticalAlignment     = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(
                imageVector = if (selected) item.selectedIcon else item.unselectedIcon,
                contentDescription = item.label,
                tint = if (selected) MaterialTheme.colorScheme.onSecondaryContainer
                       else          MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (selected) {
                Text(
                    text  = item.label,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    maxLines = 1
                )
            }
        }
    }
}
