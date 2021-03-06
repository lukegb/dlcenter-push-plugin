//////////////////////////////////////////////////////////////////////////////
// Clirr: compares two versions of a java library for binary compatibility
// Copyright (C) 2003  Lars K�hne
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//////////////////////////////////////////////////////////////////////////////

package net.sf.clirr.framework;

import org.apache.bcel.util.ClassSet;

/**
 * Checks for changes between two sets of classes.
 *
 * @author lkuehne
 */
public interface ClassSetChangeCheck
{
    /**
     * Checks for changes etween two sets of classes.
     * @param compatBaseline the classes of the compatibility baseline
     * @param currentVersion the classes of the current software version
     */
    void check(ClassSet compatBaseline, ClassSet currentVersion);
}
